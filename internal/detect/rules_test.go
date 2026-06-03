package detect_test

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"runtime-guard/internal/detect"
	"runtime-guard/internal/events"
)

func TestBasicAnalyzeDownloadExecuteConnectFixture(t *testing.T) {
	fixture, err := os.Open("../../testdata/events/web-download-execute-connect.json")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()

	normalizedEvents, err := events.LoadJSON(fixture)
	if err != nil {
		t.Fatal(err)
	}

	result := detect.NewBasic().Analyze(normalizedEvents)
	expected := []struct {
		ruleID      string
		scoreImpact int
		eventIDs    []string
	}{
		{"web_process_spawned_shell", 30, []string{"evt-001"}},
		{"shell_downloaded_file", 20, []string{"evt-002"}},
		{"tmp_file_made_executable", 20, []string{"evt-003"}},
		{"recently_downloaded_binary_executed", 30, []string{"evt-002", "evt-004"}},
		{"downloaded_binary_connected_outbound", 35, []string{"evt-002", "evt-004", "evt-005"}},
	}

	if len(result.Signals) != len(expected) {
		t.Fatalf("signal count = %d, want %d", len(result.Signals), len(expected))
	}
	for index, want := range expected {
		got := result.Signals[index]
		if got.RuleID != want.ruleID {
			t.Errorf("signal %d rule ID = %q, want %q", index, got.RuleID, want.ruleID)
		}
		if got.ScoreImpact != want.scoreImpact {
			t.Errorf("signal %d score impact = %d, want %d", index, got.ScoreImpact, want.scoreImpact)
		}
		if !slices.Equal(got.EventIDs, want.eventIDs) {
			t.Errorf("signal %d event IDs = %v, want %v", index, got.EventIDs, want.eventIDs)
		}
	}
	if result.RiskScore != 100 {
		t.Fatalf("risk score = %d, want capped score 100", result.RiskScore)
	}
}

func TestBasicAnalyzeLearnsDownloadedPathFromFileWrite(t *testing.T) {
	normalizedEvents := loadFixture(t, "../../testdata/events/web-download-execute-connect.json")
	normalizedEvents[1].CommandLine = []string{"/usr/bin/curl"}
	fileWrite := events.Event{
		EventID:           "evt-write",
		Timestamp:         time.Date(2026, time.June, 2, 10, 15, 31, 0, time.UTC),
		Host:              "devbox-01",
		ContainerID:       "9f6d7e8a",
		ContainerName:     "frontend",
		PID:               4120,
		PPID:              4112,
		UID:               33,
		ProcessName:       "curl",
		ParentProcessName: "sh",
		EventType:         events.TypeFileWrite,
		ExecutablePath:    "/usr/bin/curl",
		FilePath:          "/tmp/payload",
	}
	normalizedEvents = append(normalizedEvents, fileWrite)

	result := detect.NewBasic().Analyze(normalizedEvents)
	executed := signalByRuleID(t, result, "recently_downloaded_binary_executed")
	if !slices.Equal(executed.EventIDs, []string{"evt-002", "evt-write", "evt-004"}) {
		t.Fatalf("execution evidence = %v, want curl exec, write, and payload exec", executed.EventIDs)
	}
	connected := signalByRuleID(t, result, "downloaded_binary_connected_outbound")
	if !slices.Equal(connected.EventIDs, []string{"evt-002", "evt-write", "evt-004", "evt-005"}) {
		t.Fatalf("connect evidence = %v, want curl exec, write, payload exec, and connect", connected.EventIDs)
	}
}

func TestBasicAnalyzeAdditionalRulesFixture(t *testing.T) {
	normalizedEvents := loadFixture(t, "../../testdata/events/additional-rules.json")

	result := detect.NewBasic().Analyze(normalizedEvents)
	expected := []struct {
		ruleID      string
		scoreImpact int
		eventIDs    []string
	}{
		{"package_manager_spawned_shell", 5, []string{"evt-rule-001"}},
		{"suspicious_reverse_shell_pattern", 50, []string{"evt-rule-002", "evt-rule-003"}},
		{"sensitive_file_access", 35, []string{"evt-rule-004"}},
		{"crypto_miner_process_name", 35, []string{"evt-rule-006"}},
		{"unexpected_network_tool_execution", 20, []string{"evt-rule-007"}},
	}

	if len(result.Signals) != len(expected) {
		t.Fatalf("signal count = %d, want %d", len(result.Signals), len(expected))
	}
	for index, want := range expected {
		got := result.Signals[index]
		if got.RuleID != want.ruleID {
			t.Errorf("signal %d rule ID = %q, want %q", index, got.RuleID, want.ruleID)
		}
		if got.ScoreImpact != want.scoreImpact {
			t.Errorf("signal %d score impact = %d, want %d", index, got.ScoreImpact, want.scoreImpact)
		}
		if !slices.Equal(got.EventIDs, want.eventIDs) {
			t.Errorf("signal %d event IDs = %v, want %v", index, got.EventIDs, want.eventIDs)
		}
	}
	if result.RiskScore != 100 {
		t.Fatalf("risk score = %d, want capped score 100", result.RiskScore)
	}
}

func TestBasicAnalyzeIgnoresFailedAndEmptyMutations(t *testing.T) {
	timestamp := time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC)
	normalizedEvents := []events.Event{
		{
			EventID:     "evt-failed-write",
			Timestamp:   timestamp,
			Host:        "devbox-01",
			PID:         6001,
			ProcessName: "sed",
			EventType:   events.TypeFileWrite,
			FilePath:    "/etc/shadow",
			Metadata:    map[string]any{"outcome": "failed", "written_bytes": int64(0)},
		},
		{
			EventID:     "evt-empty-write",
			Timestamp:   timestamp.Add(time.Second),
			Host:        "devbox-01",
			PID:         6001,
			ProcessName: "sed",
			EventType:   events.TypeFileWrite,
			FilePath:    "/etc/shadow",
			Metadata:    map[string]any{"outcome": "success", "written_bytes": int64(0)},
		},
		{
			EventID:     "evt-failed-chmod",
			Timestamp:   timestamp.Add(2 * time.Second),
			Host:        "devbox-01",
			PID:         6002,
			ProcessName: "chmod",
			EventType:   events.TypeChmod,
			FilePath:    "/tmp/payload",
			Metadata:    map[string]any{"outcome": "failed", "added_execute_bit": true},
		},
	}

	result := detect.NewBasic().Analyze(normalizedEvents)
	if len(result.Signals) != 0 {
		t.Fatalf("signals = %+v, want none for failed or empty mutations", result.Signals)
	}
}

func TestBasicAnalyzeFormatsIPv6EndpointEvidence(t *testing.T) {
	normalizedEvents := []events.Event{
		{
			EventID:        "evt-ipv6-shell-connect",
			Timestamp:      time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC),
			Host:           "devbox-01",
			PID:            6001,
			ProcessName:    "bash",
			EventType:      events.TypeConnect,
			ExecutablePath: "/usr/bin/bash",
			RemoteAddr:     "2001:db8::5",
			RemotePort:     4444,
		},
	}

	result := detect.NewBasic().Analyze(normalizedEvents)
	signal := signalByRuleID(t, result, "suspicious_reverse_shell_pattern")
	if want := "[2001:db8::5]:4444"; !strings.Contains(signal.Evidence, want) {
		t.Fatalf("evidence = %q, want IPv6 endpoint %q", signal.Evidence, want)
	}
}

func TestRiskLevel(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{0, "low"},
		{29, "low"},
		{30, "medium"},
		{59, "medium"},
		{60, "high"},
		{79, "high"},
		{80, "critical"},
		{100, "critical"},
	}

	for _, test := range tests {
		if got := detect.RiskLevel(test.score); got != test.want {
			t.Errorf("RiskLevel(%d) = %q, want %q", test.score, got, test.want)
		}
	}
}

func loadFixture(t *testing.T, path string) []events.Event {
	t.Helper()
	fixture, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()

	normalizedEvents, err := events.LoadJSON(fixture)
	if err != nil {
		t.Fatal(err)
	}
	return normalizedEvents
}

func signalByRuleID(t *testing.T, result detect.Result, ruleID string) detect.Signal {
	t.Helper()
	for _, signal := range result.Signals {
		if signal.RuleID == ruleID {
			return signal
		}
	}
	t.Fatalf("signal %q not found", ruleID)
	return detect.Signal{}
}
