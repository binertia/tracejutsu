package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"runtime-guard/internal/compress"
)

const (
	defaultTimeout       = 5 * time.Minute
	maxHTTPResponseBytes = 1024 * 1024
	maxErrorExcerptBytes = 1024
)

type HTTPConfig struct {
	Endpoint            string
	Model               string
	Timeout             time.Duration
	RemoteEndpointOptIn bool
	PreserveRawResponse bool
	APIKey              string
	Transport           http.RoundTripper
}

type HTTPClient struct {
	endpoint            string
	model               string
	httpClient          *http.Client
	preserveRawResponse bool
	apiKey              string
}

func NewHTTPClient(config HTTPConfig) (*HTTPClient, error) {
	endpoint, err := completionEndpoint(config.Endpoint, config.RemoteEndpointOptIn)
	if err != nil {
		return nil, err
	}
	if config.Model == "" {
		return nil, errors.New("LLM model is required")
	}
	if config.Timeout <= 0 {
		config.Timeout = defaultTimeout
	}
	transport := config.Transport
	if transport == nil {
		transport = http.DefaultTransport.(*http.Transport).Clone()
		parsedEndpoint, err := url.Parse(endpoint)
		if err != nil {
			return nil, fmt.Errorf("parse normalized LLM endpoint: %w", err)
		}
		if isLoopbackHost(parsedEndpoint.Hostname()) {
			transport.(*http.Transport).Proxy = nil
		}
	}
	return &HTTPClient{
		endpoint: endpoint,
		model:    config.Model,
		httpClient: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return errors.New("LLM endpoint redirects are refused")
			},
		},
		preserveRawResponse: config.PreserveRawResponse,
		apiKey:              config.APIKey,
	}, nil
}

func (client *HTTPClient) Analyze(ctx context.Context, incident compress.Incident) (Analysis, error) {
	prompt, err := BuildPrompt(incident)
	if err != nil {
		return Analysis{}, err
	}
	payload, err := json.Marshal(chatCompletionRequest{
		Model: client.model,
		Messages: []chatMessage{{
			Role:    "user",
			Content: prompt,
		}},
		Temperature: 0,
		Stream:      false,
		ResponseFormat: responseFormat{
			Type:   "json_object",
			Schema: reportJSONSchema(),
		},
	})
	if err != nil {
		return Analysis{}, fmt.Errorf("encode LLM request: %w", err)
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.endpoint, bytes.NewReader(payload))
	if err != nil {
		return Analysis{}, fmt.Errorf("create LLM request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	if client.apiKey != "" {
		request.Header.Set("Authorization", "Bearer "+client.apiKey)
	}

	response, err := client.httpClient.Do(request)
	if err != nil {
		return Analysis{}, fmt.Errorf("call local LLM: %w", err)
	}
	defer response.Body.Close()

	body, err := readBounded(response.Body)
	if err != nil {
		return Analysis{}, err
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return Analysis{}, fmt.Errorf("local LLM returned HTTP %d: %s", response.StatusCode, errorExcerpt(body))
	}

	var completion chatCompletionResponse
	if err := json.Unmarshal(body, &completion); err != nil {
		return Analysis{}, fmt.Errorf("decode LLM completion: %w", err)
	}
	if len(completion.Choices) == 0 || completion.Choices[0].Message.Content == "" {
		return Analysis{}, errors.New("decode LLM completion: missing assistant content")
	}

	rawResponse := completion.Choices[0].Message.Content
	report, err := decodeReport(rawResponse)
	if err != nil {
		return Analysis{}, err
	}
	analysis := Analysis{
		Report: report,
		Model:  client.model,
	}
	if client.preserveRawResponse {
		analysis.RawResponse = rawResponse
	}
	return analysis, nil
}

type chatCompletionRequest struct {
	Model          string         `json:"model"`
	Messages       []chatMessage  `json:"messages"`
	Temperature    int            `json:"temperature"`
	Stream         bool           `json:"stream"`
	ResponseFormat responseFormat `json:"response_format"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type   string     `json:"type"`
	Schema jsonSchema `json:"schema"`
}

type jsonSchema struct {
	Type                 string                `json:"type"`
	Properties           map[string]jsonSchema `json:"properties,omitempty"`
	Required             []string              `json:"required,omitempty"`
	AdditionalProperties *bool                 `json:"additionalProperties,omitempty"`
	Enum                 []string              `json:"enum,omitempty"`
	Items                *jsonSchema           `json:"items,omitempty"`
}

func reportJSONSchema() jsonSchema {
	noAdditionalProperties := false
	stringSchema := jsonSchema{Type: "string"}
	stringListSchema := jsonSchema{
		Type:  "array",
		Items: &stringSchema,
	}

	return jsonSchema{
		Type: "object",
		Properties: map[string]jsonSchema{
			"summary":                      stringSchema,
			"risk_level":                   {Type: "string", Enum: []string{"low", "medium", "high", "critical"}},
			"likely_behavior":              stringSchema,
			"why_suspicious":               stringListSchema,
			"false_positive_possibilities": stringListSchema,
			"recommended_commands":         stringListSchema,
			"containment_advice":           stringListSchema,
		},
		Required: []string{
			"summary",
			"risk_level",
			"likely_behavior",
			"why_suspicious",
			"false_positive_possibilities",
			"recommended_commands",
			"containment_advice",
		},
		AdditionalProperties: &noAdditionalProperties,
	}
}

type chatCompletionResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
}

func completionEndpoint(endpoint string, remoteEndpointOptIn bool) (string, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parse LLM endpoint: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", errors.New("LLM endpoint scheme must be http or https")
	}
	if parsed.Host == "" {
		return "", errors.New("LLM endpoint host is required")
	}
	if parsed.User != nil {
		return "", errors.New("LLM endpoint must not include credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("LLM endpoint must not include a query or fragment")
	}
	if !remoteEndpointOptIn && !isLoopbackHost(parsed.Hostname()) {
		return "", fmt.Errorf("refusing non-loopback LLM endpoint %q without explicit remote opt-in", parsed.Hostname())
	}

	parsed.Path = strings.TrimSuffix(parsed.Path, "/")
	switch {
	case strings.HasSuffix(parsed.Path, "/v1/chat/completions"):
	case strings.HasSuffix(parsed.Path, "/v1"):
		parsed.Path += "/chat/completions"
	default:
		parsed.Path += "/v1/chat/completions"
	}
	return parsed.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func readBounded(reader io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxHTTPResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read LLM response: %w", err)
	}
	if len(body) > maxHTTPResponseBytes {
		return nil, fmt.Errorf("read LLM response: exceeds %d bytes", maxHTTPResponseBytes)
	}
	return body, nil
}

func errorExcerpt(body []byte) string {
	if len(body) > maxErrorExcerptBytes {
		body = body[:maxErrorExcerptBytes]
	}
	return strings.TrimSpace(string(body))
}

func decodeReport(rawResponse string) (Report, error) {
	var report Report
	decoder := json.NewDecoder(strings.NewReader(rawResponse))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return Report{}, fmt.Errorf("decode LLM report: %w", err)
	}
	if err := ensureEOF(decoder); err != nil {
		return Report{}, err
	}
	if err := ValidateReport(report); err != nil {
		return Report{}, fmt.Errorf("validate LLM report: %w", err)
	}
	return report, nil
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("decode LLM report: trailing JSON value")
		}
		return fmt.Errorf("decode LLM report: trailing data: %w", err)
	}
	return nil
}
