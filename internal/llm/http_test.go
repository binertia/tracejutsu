package llm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"runtime-guard/internal/compress"
)

func TestHTTPClientAnalyze(t *testing.T) {
	var received chatCompletionRequest
	transport := roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path != "/v1/chat/completions" {
			t.Errorf("request path = %q, want /v1/chat/completions", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("authorization header = %q, want bearer token", request.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil {
			t.Error(err)
			return newHTTPResponse(http.StatusBadRequest, "bad request"), nil
		}
		return newCompletionResponse(validReportJSON()), nil
	})

	client, err := NewHTTPClient(HTTPConfig{
		Endpoint:  "http://127.0.0.1",
		Model:     "test-model",
		APIKey:    "secret",
		Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := client.Analyze(context.Background(), fixtureIncident())
	if err != nil {
		t.Fatal(err)
	}

	if analysis.Report.RiskLevel != "critical" {
		t.Fatalf("risk level = %q, want critical", analysis.Report.RiskLevel)
	}
	if analysis.Model != "test-model" {
		t.Fatalf("model = %q, want test-model", analysis.Model)
	}
	if analysis.RawResponse != "" {
		t.Fatalf("raw response = %q, want empty by default", analysis.RawResponse)
	}
	if received.Model != "test-model" {
		t.Fatalf("request model = %q, want test-model", received.Model)
	}
	if len(received.Messages) != 1 || !strings.Contains(received.Messages[0].Content, `"incident_id": "inc-test"`) {
		t.Fatalf("request prompt did not contain compressed incident: %+v", received.Messages)
	}
	if strings.Contains(received.Messages[0].Content, `"command_line"`) {
		t.Fatal("request prompt unexpectedly contained raw event fields")
	}
	if received.ResponseFormat.Type != "json_object" {
		t.Fatalf("response format = %q, want json_object", received.ResponseFormat.Type)
	}
	schema := received.ResponseFormat.Schema
	if schema.Type != "object" {
		t.Fatalf("response schema type = %q, want object", schema.Type)
	}
	if schema.AdditionalProperties == nil || *schema.AdditionalProperties {
		t.Fatal("response schema must reject additional properties")
	}
	for _, field := range []string{
		"why_suspicious",
		"false_positive_possibilities",
		"recommended_commands",
		"containment_advice",
	} {
		property := schema.Properties[field]
		if property.Type != "array" || property.Items == nil || property.Items.Type != "string" {
			t.Fatalf("response schema property %q = %+v, want array of strings", field, property)
		}
	}
}

func TestHTTPClientPreservesRawResponseOnlyWhenConfigured(t *testing.T) {
	rawReport := validReportJSON()
	transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return newCompletionResponse(rawReport), nil
	})

	client, err := NewHTTPClient(HTTPConfig{
		Endpoint:            "http://127.0.0.1",
		Model:               "test-model",
		PreserveRawResponse: true,
		Transport:           transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := client.Analyze(context.Background(), fixtureIncident())
	if err != nil {
		t.Fatal(err)
	}
	if analysis.RawResponse != rawReport {
		t.Fatalf("raw response = %q, want preserved report", analysis.RawResponse)
	}
}

func TestHTTPClientRejectsInvalidReports(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"unknown key", strings.TrimSuffix(validReportJSON(), "}") + `,"invented":"value"}`},
		{"invalid risk", strings.Replace(validReportJSON(), `"critical"`, `"severe"`, 1)},
		{"string instead of list", strings.Replace(validReportJSON(), `"why_suspicious":["Downloaded binary connected outbound."]`, `"why_suspicious":"Downloaded binary connected outbound."`, 1)},
		{"missing list", strings.Replace(validReportJSON(), `"containment_advice":["review manually"]`, `"containment_advice":null`, 1)},
		{"trailing JSON", validReportJSON() + `{}`},
		{"markdown fence", "```json\n" + validReportJSON() + "\n```"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			transport := roundTripperFunc(func(*http.Request) (*http.Response, error) {
				return newCompletionResponse(test.raw), nil
			})

			client, err := NewHTTPClient(HTTPConfig{
				Endpoint:  "http://127.0.0.1",
				Model:     "test-model",
				Transport: transport,
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.Analyze(context.Background(), fixtureIncident()); err == nil {
				t.Fatal("expected invalid LLM report error")
			}
		})
	}
}

func TestNewHTTPClientRejectsRemoteEndpointWithoutOptIn(t *testing.T) {
	if _, err := NewHTTPClient(HTTPConfig{
		Endpoint: "https://llm.example.com",
		Model:    "test-model",
	}); err == nil {
		t.Fatal("expected remote endpoint rejection")
	}
	if _, err := NewHTTPClient(HTTPConfig{
		Endpoint:            "https://llm.example.com",
		Model:               "test-model",
		RemoteEndpointOptIn: true,
	}); err != nil {
		t.Fatalf("explicit remote endpoint opt-in failed: %v", err)
	}
}

func TestHTTPClientEnforcesTimeout(t *testing.T) {
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		select {
		case <-time.After(50 * time.Millisecond):
			return newCompletionResponse(validReportJSON()), nil
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	})

	client, err := NewHTTPClient(HTTPConfig{
		Endpoint:  "http://127.0.0.1",
		Model:     "test-model",
		Timeout:   5 * time.Millisecond,
		Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Analyze(context.Background(), fixtureIncident()); err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestHTTPClientRefusesRedirects(t *testing.T) {
	targetCalls := 0
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Path {
		case "/v1/chat/completions":
			return &http.Response{
				StatusCode: http.StatusTemporaryRedirect,
				Status:     http.StatusText(http.StatusTemporaryRedirect),
				Header: http.Header{
					"Location": []string{"http://127.0.0.1/v1/chat/completions"},
				},
				Body:    io.NopCloser(strings.NewReader("redirect")),
				Request: req,
			}, nil
		default:
			targetCalls++
			return newCompletionResponse(validReportJSON()), nil
		}
	})

	client, err := NewHTTPClient(HTTPConfig{
		Endpoint:  "http://127.0.0.1",
		Model:     "test-model",
		Transport: transport,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Analyze(context.Background(), fixtureIncident()); err == nil {
		t.Fatal("expected redirect refusal")
	}
	if targetCalls != 0 {
		t.Fatalf("redirect target calls = %d, want 0", targetCalls)
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (fn roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func newCompletionResponse(report string) *http.Response {
	return newHTTPResponse(http.StatusOK, map[string]any{
		"choices": []any{
			map[string]any{
				"message": map[string]string{
					"role":    "assistant",
					"content": report,
				},
			},
		},
	})
}

func newHTTPResponse(status int, payload any) *http.Response {
	body, _ := json.Marshal(payload)
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(body))),
	}
}

func validReportJSON() string {
	return `{"summary":"Suspicious runtime chain.","risk_level":"critical","likely_behavior":"Possible payload execution.","why_suspicious":["Downloaded binary connected outbound."],"false_positive_possibilities":["Administrative test."],"recommended_commands":["ps -fp 4131"],"containment_advice":["review manually"]}`
}

func fixtureIncident() compress.Incident {
	return compress.Incident{
		IncidentID: "inc-test",
		RiskScore:  100,
		Signals:    []string{"downloaded_binary_connected_outbound"},
		Timeline:   []string{"/tmp/payload connected to 203.0.113.10:4444"},
		LLMStatus:  "pending",
	}
}
