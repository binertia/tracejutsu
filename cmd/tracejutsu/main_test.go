package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tracejutsu/internal/compress"
	sensor "tracejutsu/internal/ebpf"
	"tracejutsu/internal/events"
	"tracejutsu/internal/llm"
	"tracejutsu/internal/store"
)

type stubLLMClient struct{}

func (stubLLMClient) Analyze(context.Context, compress.Incident) (llm.Analysis, error) {
	return llm.Analysis{
		Model: "test-model",
		Report: llm.Report{
			Summary:                    "Likely payload execution chain.",
			RiskLevel:                  "high",
			LikelyBehavior:             "Possible web application compromise.",
			WhySuspicious:              []string{"A downloaded binary connected outbound."},
			FalsePositivePossibilities: []string{"Authorized security test."},
			RecommendedCommands:        []string{"ps -fp 4131"},
			ContainmentAdvice:          []string{"Review the process before taking manual action."},
		},
	}, nil
}

type statsRuntimeCollector struct{}

func (statsRuntimeCollector) Run(context.Context, chan<- events.Event) error {
	return nil
}

func (statsRuntimeCollector) Stats() sensor.Stats {
	return sensor.Stats{RingBufferDropped: 7, CorrelationDropped: 3}
}

func (statsRuntimeCollector) StatsByCollector() []sensor.CollectorStats {
	return []sensor.CollectorStats{
		{Name: "execve", Stats: sensor.Stats{RingBufferDropped: 2}},
		{Name: "file_write", Stats: sensor.Stats{RingBufferDropped: 5, CorrelationDropped: 3}},
	}
}

func TestWriteLiveStats(t *testing.T) {
	processor := newProcessor(time.Second)
	if _, err := processor.Add(events.Event{
		EventID:     "evt-benign",
		Timestamp:   time.Date(2026, time.June, 3, 12, 0, 0, 0, time.UTC),
		Host:        "devbox-01",
		PID:         100,
		ProcessName: "true",
		EventType:   events.TypeExecve,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := processor.Drain(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	writeLiveStats(&output, statsRuntimeCollector{}, processor, nil, nil, 1)
	for _, expected := range []string{
		"normalized=1",
		"grouped=1",
		"analyzed=1",
		"incidents=0",
		"ring_dropped=7",
		"correlation_dropped=3",
		"collector_ring_dropped=execve:2,file_write:5",
		"collector_correlation_dropped=execve:0,file_write:3",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output = %q, want substring %q", output.String(), expected)
		}
	}
}

func TestWriteLiveEventHonorsQuietMode(t *testing.T) {
	event := events.Event{
		EventID:     "evt-quiet-test",
		Timestamp:   time.Date(2026, time.June, 3, 12, 0, 0, 0, time.UTC),
		Host:        "devbox-01",
		PID:         100,
		ProcessName: "true",
		EventType:   events.TypeExecve,
	}

	var verboseOutput bytes.Buffer
	if err := writeLiveEvent(json.NewEncoder(&verboseOutput), event, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verboseOutput.String(), "evt-quiet-test") {
		t.Fatalf("verbose output = %q, want event JSON", verboseOutput.String())
	}

	var quietOutput bytes.Buffer
	if err := writeLiveEvent(json.NewEncoder(&quietOutput), event, true); err != nil {
		t.Fatal(err)
	}
	if quietOutput.Len() != 0 {
		t.Fatalf("quiet output = %q, want empty output", quietOutput.String())
	}
}

func TestOptionalTicker(t *testing.T) {
	ticker, ticks, err := optionalTicker(0)
	if err != nil {
		t.Fatal(err)
	}
	if ticker != nil || ticks != nil {
		t.Fatalf("disabled ticker = (%v, %v), want nil ticker and nil channel", ticker, ticks)
	}

	ticker, ticks, err = optionalTicker(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer ticker.Stop()
	if ticker == nil || ticks == nil {
		t.Fatalf("enabled ticker = (%v, %v), want ticker and channel", ticker, ticks)
	}

	if _, _, err := optionalTicker(-time.Second); err == nil {
		t.Fatal("expected negative interval to fail")
	}
}

func TestStatsIntervalLabel(t *testing.T) {
	if got := statsIntervalLabel(0); got != "disabled" {
		t.Fatalf("disabled label = %q, want disabled", got)
	}
	if got := statsIntervalLabel(2 * time.Minute); got != "2m0s" {
		t.Fatalf("duration label = %q, want 2m0s", got)
	}
}

func TestRunVersion(t *testing.T) {
	previousVersion := buildVersion
	previousCommit := buildCommit
	previousDate := buildDate
	buildVersion = "v1.2.3"
	buildCommit = "abc123"
	buildDate = "2026-06-04T10:00:00Z"
	defer func() {
		buildVersion = previousVersion
		buildCommit = previousCommit
		buildDate = previousDate
	}()

	var output bytes.Buffer
	if err := run([]string{"version"}, &output); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"tracejutsu v1.2.3",
		"commit: abc123",
		"build_date: 2026-06-04T10:00:00Z",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output = %q, want substring %q", output.String(), expected)
		}
	}

	if err := run([]string{"version", "extra"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected usage error")
	}
}

func TestRunLiveRejectsInvalidBufferOptions(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		want string
	}{
		{
			name: "event buffer",
			args: []string{"run", "--event-buffer", "0"},
			want: "event buffer size must be positive",
		},
		{
			name: "persist buffer",
			args: []string{"run", "--persist-buffer", "0"},
			want: "persist buffer size must be positive",
		},
		{
			name: "persist batch size",
			args: []string{"run", "--persist-batch-size", "0"},
			want: "persist batch size must be positive",
		},
		{
			name: "ring buffer positive",
			args: []string{"run", "--ring-buffer-size", "0"},
			want: "ring buffer size must be positive",
		},
		{
			name: "ring buffer power of two",
			args: []string{"run", "--ring-buffer-size", "12582912"},
			want: "collector ring buffer size must be a power of two",
		},
		{
			name: "unknown collector",
			args: []string{"run", "--collectors", "unknown"},
			want: "unknown collector",
		},
		{
			name: "file write minimum bytes",
			args: []string{"run", "--file-write-min-bytes", "-1"},
			want: "file write minimum bytes must be non-negative",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := run(test.args, &bytes.Buffer{})
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %q, want substring %q", err.Error(), test.want)
			}
		})
	}
}

func TestRunLLMAnalyzesStoredIncident(t *testing.T) {
	databaseDirectory := t.TempDir()
	if err := os.Chmod(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(databaseDirectory, "tracejutsu.db")
	if err := run([]string{
		"demo",
		"--db", databasePath,
		"../../testdata/events/web-download-execute-connect.json",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var deterministicOutput bytes.Buffer
	if err := run([]string{
		"show",
		"--db", databasePath,
		"inc-evt-001",
	}, &deterministicOutput); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(deterministicOutput.String(), "LLM ANALYSIS") {
		t.Fatalf("output = %q, want deterministic report only before LLM analysis", deterministicOutput.String())
	}

	previousFactory := newLLMClient
	newLLMClient = func(llm.HTTPConfig) (llm.Client, error) {
		return stubLLMClient{}, nil
	}
	defer func() {
		newLLMClient = previousFactory
	}()

	var output bytes.Buffer
	if err := run([]string{
		"llm",
		"--db", databasePath,
		"--endpoint", "http://127.0.0.1:8080",
		"--model", "test-model",
		"inc-evt-001",
	}, &output); err != nil {
		t.Fatal(err)
	}

	for _, expected := range []string{
		"LLM ANALYSIS inc-evt-001",
		"deterministic risk: critical (score=100)",
		"llm risk: high (disagrees with deterministic score)",
		"Possible web application compromise.",
		"ps -fp 4131",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output = %q, want substring %q", output.String(), expected)
		}
	}

	database, err := store.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	stored, err := database.GetLLMReport(context.Background(), "inc-evt-001")
	if err != nil {
		t.Fatal(err)
	}
	if stored.Model != "test-model" {
		t.Fatalf("stored model = %q, want test-model", stored.Model)
	}
	if stored.RawResponse != "" {
		t.Fatalf("stored raw response = %q, want empty by default", stored.RawResponse)
	}

	var showOutput bytes.Buffer
	if err := run([]string{
		"show",
		"--db", databasePath,
		"inc-evt-001",
	}, &showOutput); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"INCIDENT inc-evt-001",
		"Evidence events: 5",
		"LLM ANALYSIS inc-evt-001",
		"llm risk: high (disagrees with deterministic score)",
		"ps -fp 4131",
	} {
		if !strings.Contains(showOutput.String(), expected) {
			t.Fatalf("output = %q, want substring %q", showOutput.String(), expected)
		}
	}
}

func TestRunLLMAllPendingAnalyzesBatch(t *testing.T) {
	databasePath := createDemoDatabase(t)

	previousFactory := newLLMClient
	newLLMClient = func(llm.HTTPConfig) (llm.Client, error) {
		return stubLLMClient{}, nil
	}
	defer func() {
		newLLMClient = previousFactory
	}()

	var output bytes.Buffer
	if err := run([]string{
		"llm",
		"--db", databasePath,
		"--endpoint", "http://127.0.0.1:8080",
		"--model", "test-model",
		"--all-pending",
		"--min-score", "50",
		"--limit", "5",
	}, &output); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"LLM ANALYSIS inc-evt-001",
		"llm batch: processed=1 complete=1 failed=0",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output = %q, want substring %q", output.String(), expected)
		}
	}

	database, err := store.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	incident, _, err := database.GetIncident(context.Background(), "inc-evt-001")
	if err != nil {
		t.Fatal(err)
	}
	if incident.LLMStatus != "complete" {
		t.Fatalf("LLM status = %q, want complete", incident.LLMStatus)
	}
}

func TestRunTriageShowsPrioritizedDemoIncident(t *testing.T) {
	databaseDirectory := t.TempDir()
	if err := os.Chmod(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(databaseDirectory, "tracejutsu.db")
	if err := run([]string{
		"demo",
		"--db", databasePath,
		"../../testdata/events/web-download-execute-connect.json",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := run([]string{
		"triage",
		"--db", databasePath,
		"--evidence-limit", "2",
	}, &output); err != nil {
		t.Fatal(err)
	}

	for _, expected := range []string{
		"triage incidents",
		"INCIDENT inc-evt-001  CRITICAL  score=100",
		"llm=pending  evidence=5",
		"summary: nginx spawned a shell",
		"signals:",
		"web_process_spawned_shell",
		"timeline:",
		"nginx spawned shell sh",
		"evidence:",
		"evt-001 execve",
		"... 3 more",
		"next: tracejutsu show --db " + databasePath + " inc-evt-001",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output = %q, want substring %q", output.String(), expected)
		}
	}
}

func TestRunTriageFiltersLimitsAndValidatesOptions(t *testing.T) {
	databaseDirectory := t.TempDir()
	if err := os.Chmod(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(databaseDirectory, "tracejutsu.db")
	database, err := store.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	normalizedEvents := loadMainFixture(t)
	if err := database.SaveEvents(context.Background(), normalizedEvents); err != nil {
		t.Fatal(err)
	}
	incidents := []compress.Incident{
		mainTestIncident("inc-low", 25, time.Date(2026, time.June, 4, 10, 0, 0, 0, time.UTC), "low summary"),
		mainTestIncident("inc-high-old", 80, time.Date(2026, time.June, 4, 11, 0, 0, 0, time.UTC), "old summary"),
		mainTestIncident("inc-high-new", 80, time.Date(2026, time.June, 4, 12, 0, 0, 0, time.UTC), "new summary"),
	}
	for _, incident := range incidents {
		if err := database.SaveIncident(context.Background(), incident); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.LinkIncidentEvents(context.Background(), "inc-high-new", []string{"evt-001"}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := run([]string{
		"triage",
		"--db", databasePath,
		"--min-score", "80",
		"--limit", "1",
		"--evidence-limit", "0",
	}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "INCIDENT inc-high-new") {
		t.Fatalf("output = %q, want newest high-scoring incident first", output.String())
	}
	for _, unexpected := range []string{"inc-high-old", "inc-low", "evidence:"} {
		if strings.Contains(output.String(), unexpected) {
			t.Fatalf("output = %q, did not want %q", output.String(), unexpected)
		}
	}

	var none bytes.Buffer
	if err := run([]string{
		"triage",
		"--db", databasePath,
		"--min-score", "101",
	}, &none); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(none.String(), "triage incidents\n  none\n") {
		t.Fatalf("output = %q, want no incidents", none.String())
	}

	for _, args := range [][]string{
		{"triage", "--db", databasePath, "--min-score", "-1"},
		{"triage", "--db", databasePath, "--evidence-limit", "-1"},
		{"triage", "--db", databasePath, "extra"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("args %v: expected error", args)
		}
	}
}

func TestRunTriageSanitizesTerminalControlledText(t *testing.T) {
	databaseDirectory := t.TempDir()
	if err := os.Chmod(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(databaseDirectory, "tracejutsu.db")
	database, err := store.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	event := events.Event{
		EventID:        "evt-\x1b[2J",
		Timestamp:      time.Date(2026, time.June, 4, 12, 0, 0, 0, time.UTC),
		Host:           "devbox-01",
		PID:            42,
		ProcessName:    "curl\nforged",
		EventType:      events.TypeExecve,
		ExecutablePath: "/tmp/payload\rhidden",
	}
	if err := database.SaveEvent(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	incident := mainTestIncident("inc-\x1b[2J", 90, time.Date(2026, time.June, 4, 12, 0, 0, 0, time.UTC), "summary\rrewritten")
	incident.Signals = []string{"signal\u202eoverride"}
	incident.Timeline = []string{"timeline\tshifted"}
	if err := database.SaveIncident(context.Background(), incident); err != nil {
		t.Fatal(err)
	}
	if err := database.LinkIncidentEvents(context.Background(), incident.IncidentID, []string{event.EventID}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := run([]string{"triage", "--db", databasePath}, &output); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(output.String(), '\x1b') || strings.ContainsRune(output.String(), '\u202e') {
		t.Fatalf("output contains unsafe terminal text: %q", output.String())
	}
	for _, expected := range []string{
		"inc-?[2J",
		"summary?rewritten",
		"signal?override",
		"timeline?shifted",
		"evt-?[2J execve",
		"curl?forged",
		"/tmp/payload?hidden",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output = %q, want substring %q", output.String(), expected)
		}
	}
}

func TestRunInitAndDoctorUseDefaultStatePath(t *testing.T) {
	stateHome := t.TempDir()
	if err := os.Chmod(stateHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRACEJUTSU_DB", "")
	t.Setenv("XDG_STATE_HOME", stateHome)
	databasePath := filepath.Join(stateHome, "tracejutsu", "tracejutsu.db")

	var initOutput bytes.Buffer
	if err := run([]string{"init"}, &initOutput); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(initOutput.String(), databasePath) {
		t.Fatalf("init output = %q, want database path %q", initOutput.String(), databasePath)
	}
	info, err := os.Stat(filepath.Dir(databasePath))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("state dir permissions = %04o, want 0700", got)
	}

	var doctorOutput bytes.Buffer
	if err := run([]string{"doctor"}, &doctorOutput); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"tracejutsu doctor", "OK   database", "OK   journal_mode"} {
		if !strings.Contains(doctorOutput.String(), expected) {
			t.Fatalf("doctor output = %q, want substring %q", doctorOutput.String(), expected)
		}
	}
}

func TestCommandsUseTracejutsuDBDefaultAndFilterEvents(t *testing.T) {
	databasePath := createDemoDatabase(t)
	t.Setenv("TRACEJUTSU_DB", databasePath)

	var eventsOutput bytes.Buffer
	if err := run([]string{
		"events",
		"--type", "execve",
		"--process", "payload",
		"--pid", "4131",
		"--container-id", "9f6d7e8a",
		"--since", "2026-06-02T10:15:33Z",
		"--until", "2026-06-02T10:15:33Z",
	}, &eventsOutput); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(eventsOutput.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("events output = %q, want one JSON line", eventsOutput.String())
	}
	var event events.Event
	if err := json.Unmarshal([]byte(lines[0]), &event); err != nil {
		t.Fatal(err)
	}
	if event.EventID != "evt-004" {
		t.Fatalf("event ID = %q, want evt-004", event.EventID)
	}

	var incidentsOutput bytes.Buffer
	if err := run([]string{
		"incidents",
		"--llm-status", "pending",
		"--since", "2026-06-02T10:15:00Z",
		"--until", "2026-06-02T10:16:00Z",
		"--format", "json",
	}, &incidentsOutput); err != nil {
		t.Fatal(err)
	}
	var incidents []compress.Incident
	if err := json.Unmarshal(incidentsOutput.Bytes(), &incidents); err != nil {
		t.Fatal(err)
	}
	if len(incidents) != 1 || incidents[0].IncidentID != "inc-evt-001" {
		t.Fatalf("incidents = %+v, want inc-evt-001", incidents)
	}
}

func TestRunShowEvidencePreviewAndJSON(t *testing.T) {
	databasePath := createDemoDatabase(t)

	var textOutput bytes.Buffer
	if err := run([]string{
		"show",
		"--db", databasePath,
		"--evidence-limit", "2",
		"inc-evt-001",
	}, &textOutput); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"Evidence events: 5", "evt-001 execve", "... 3 more"} {
		if !strings.Contains(textOutput.String(), expected) {
			t.Fatalf("show output = %q, want substring %q", textOutput.String(), expected)
		}
	}

	var jsonOutput bytes.Buffer
	if err := run([]string{
		"show",
		"--db", databasePath,
		"--format", "json",
		"inc-evt-001",
	}, &jsonOutput); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		Incident       compress.Incident `json:"incident"`
		EvidenceEvents []events.Event    `json:"evidence_events"`
	}
	if err := json.Unmarshal(jsonOutput.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Incident.IncidentID != "inc-evt-001" || len(payload.EvidenceEvents) != 5 {
		t.Fatalf("show JSON = %+v, want incident and five evidence events", payload)
	}
}

func TestRunJSONOutputFormats(t *testing.T) {
	databasePath := createDemoDatabase(t)
	for _, args := range [][]string{
		{"db-stats", "--db", databasePath, "--format", "json"},
		{"event-summary", "--db", databasePath, "--format", "json"},
		{"triage", "--db", databasePath, "--format", "json"},
	} {
		var output bytes.Buffer
		if err := run(args, &output); err != nil {
			t.Fatalf("args %v: %v", args, err)
		}
		if !json.Valid(output.Bytes()) {
			t.Fatalf("args %v output is not valid JSON: %q", args, output.String())
		}
	}
}

func TestRunRulesFormats(t *testing.T) {
	var textOutput bytes.Buffer
	if err := run([]string{"rules"}, &textOutput); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"web_process_spawned_shell", "score=30", "collectors=execve"} {
		if !strings.Contains(textOutput.String(), expected) {
			t.Fatalf("rules output = %q, want substring %q", textOutput.String(), expected)
		}
	}

	var jsonOutput bytes.Buffer
	if err := run([]string{"rules", "--format", "json"}, &jsonOutput); err != nil {
		t.Fatal(err)
	}
	var definitions []struct {
		RuleID      string   `json:"rule_id"`
		ScoreImpact int      `json:"score_impact"`
		Collectors  []string `json:"collectors"`
	}
	if err := json.Unmarshal(jsonOutput.Bytes(), &definitions); err != nil {
		t.Fatal(err)
	}
	if len(definitions) == 0 || definitions[0].RuleID != "web_process_spawned_shell" || definitions[0].ScoreImpact != 30 {
		t.Fatalf("definitions = %+v, want first rule metadata", definitions)
	}
}

func TestSQLitePathHintForPermissiveParent(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}

	err := run([]string{
		"demo",
		"--db", filepath.Join(parent, "tracejutsu.db"),
		"../../testdata/events/web-download-execute-connect.json",
	}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "hint:") {
		t.Fatalf("error = %q, want actionable hint", err.Error())
	}
}

func TestRunEventSummary(t *testing.T) {
	databaseDirectory := t.TempDir()
	if err := os.Chmod(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(databaseDirectory, "tracejutsu.db")
	database, err := store.OpenSQLite(databasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveEvents(context.Background(), []events.Event{
		{
			EventID:        "evt-write-1",
			Timestamp:      time.Date(2026, time.June, 3, 21, 0, 0, 0, time.UTC),
			Host:           "devbox-01",
			PID:            100,
			ProcessName:    "curl",
			EventType:      events.TypeFileWrite,
			ExecutablePath: "/usr/bin/curl",
			FilePath:       "/tmp/payload",
		},
		{
			EventID:        "evt-write-2",
			Timestamp:      time.Date(2026, time.June, 3, 21, 0, 1, 0, time.UTC),
			Host:           "devbox-01",
			PID:            100,
			ProcessName:    "curl",
			EventType:      events.TypeFileWrite,
			ExecutablePath: "/usr/bin/curl",
			FilePath:       "/tmp/payload",
		},
		{
			EventID:        "evt-write-3",
			Timestamp:      time.Date(2026, time.June, 3, 21, 0, 2, 0, time.UTC),
			Host:           "devbox-01",
			PID:            200,
			ProcessName:    "firefox",
			EventType:      events.TypeFileWrite,
			ExecutablePath: "/usr/lib/firefox/firefox",
			FilePath:       "/home/james/.cache/browser",
		},
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := run([]string{
		"event-summary",
		"--db", databasePath,
		"--type", "file_write",
		"--limit", "2",
	}, &output); err != nil {
		t.Fatal(err)
	}

	for _, expected := range []string{
		"event summary: type=file_write",
		"Top processes:",
		"2  curl",
		"/usr/bin/curl",
		"1  firefox",
		"Top file paths:",
		"2  /tmp/payload",
		"1  /home/james/.cache/browser",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output = %q, want substring %q", output.String(), expected)
		}
	}
}

func TestRunDBStats(t *testing.T) {
	databaseDirectory := t.TempDir()
	if err := os.Chmod(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(databaseDirectory, "tracejutsu.db")
	if err := run([]string{
		"demo",
		"--db", databasePath,
		"../../testdata/events/web-download-execute-connect.json",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := run([]string{"db-stats", "--db", databasePath}, &output); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"database stats",
		"path: " + databasePath,
		"journal_mode: wal",
		"database_bytes:",
		"wal_bytes:",
		"shm_bytes:",
		"events: 5",
		"incidents: 1",
		"incident_event_links: 5",
		"llm_reports: 0",
	} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("output = %q, want substring %q", output.String(), expected)
		}
	}

	if err := run([]string{"db-stats", "--db", databasePath, "extra"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected usage error")
	}
	if err := run([]string{"db-stats", "--db", ":memory:"}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected in-memory database error")
	}
}

func TestInspectionCommandsRejectMissingDatabase(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "events", args: []string{"events"}},
		{name: "event-summary", args: []string{"event-summary"}},
		{name: "db-stats", args: []string{"db-stats"}},
		{name: "incidents", args: []string{"incidents"}},
		{name: "triage", args: []string{"triage"}},
		{name: "show", args: []string{"show", "inc-missing"}},
		{name: "llm", args: []string{"llm", "inc-missing"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			databaseDirectory := t.TempDir()
			if err := os.Chmod(databaseDirectory, 0o700); err != nil {
				t.Fatal(err)
			}
			databasePath := filepath.Join(databaseDirectory, "missing.db")
			args := append([]string{test.args[0], "--db", databasePath}, test.args[1:]...)

			err := run(args, &bytes.Buffer{})
			if err == nil {
				t.Fatal("expected missing database error")
			}
			if !strings.Contains(err.Error(), "SQLite database does not exist") {
				t.Fatalf("error = %q, want missing database", err.Error())
			}
			if _, statErr := os.Stat(databasePath); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("database stat error = %v, want not exist", statErr)
			}
		})
	}
}

func loadMainFixture(t *testing.T) []events.Event {
	t.Helper()
	fixture, err := os.Open("../../testdata/events/web-download-execute-connect.json")
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

func createDemoDatabase(t *testing.T) string {
	t.Helper()
	databaseDirectory := t.TempDir()
	if err := os.Chmod(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(databaseDirectory, "tracejutsu.db")
	if err := run([]string{
		"demo",
		"--db", databasePath,
		"../../testdata/events/web-download-execute-connect.json",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	return databasePath
}

func mainTestIncident(id string, score int, start time.Time, summary string) compress.Incident {
	return compress.Incident{
		IncidentID: id,
		StartTime:  start,
		EndTime:    start.Add(time.Minute),
		RootProcess: compress.RootProcess{
			PID:         score,
			ProcessName: "proc",
		},
		RiskScore: score,
		Signals:   []string{"test_signal"},
		Timeline:  []string{"test timeline"},
		Summary:   summary,
		LLMStatus: "pending",
	}
}
