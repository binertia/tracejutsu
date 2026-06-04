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

	"runtime-guard/internal/compress"
	sensor "runtime-guard/internal/ebpf"
	"runtime-guard/internal/events"
	"runtime-guard/internal/llm"
	"runtime-guard/internal/store"
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
		"runtime-guard v1.2.3",
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
	databasePath := filepath.Join(databaseDirectory, "runtime-guard.db")
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

func TestRunEventSummary(t *testing.T) {
	databaseDirectory := t.TempDir()
	if err := os.Chmod(databaseDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(databaseDirectory, "runtime-guard.db")
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

func TestInspectionCommandsRejectMissingDatabase(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "events", args: []string{"events"}},
		{name: "event-summary", args: []string{"event-summary"}},
		{name: "incidents", args: []string{"incidents"}},
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
