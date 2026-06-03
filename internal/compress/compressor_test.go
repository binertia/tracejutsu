package compress_test

import (
	"os"
	"slices"
	"testing"
	"time"

	"runtime-guard/internal/compress"
	"runtime-guard/internal/detect"
	"runtime-guard/internal/events"
)

func TestCompressDownloadExecuteConnectChain(t *testing.T) {
	fixture, err := os.Open("../../testdata/events/web-download-execute-connect.json")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()

	normalizedEvents, err := events.LoadJSON(fixture)
	if err != nil {
		t.Fatal(err)
	}

	detection := detect.NewBasic().Analyze(normalizedEvents)
	incident, err := compress.NewBasic().Compress(normalizedEvents, detection)
	if err != nil {
		t.Fatal(err)
	}

	const wantSummary = "nginx spawned a shell, downloaded a file into /tmp, made it executable, executed it, then opened an outbound connection."
	if incident.Summary != wantSummary {
		t.Fatalf("summary = %q, want %q", incident.Summary, wantSummary)
	}
	if incident.RiskScore != 100 {
		t.Fatalf("risk score = %d, want 100", incident.RiskScore)
	}
	if len(incident.Signals) != 5 {
		t.Fatalf("signal count = %d, want 5", len(incident.Signals))
	}
	if len(incident.Timeline) != 5 {
		t.Fatalf("timeline entry count = %d, want 5", len(incident.Timeline))
	}
	if incident.LLMStatus != "pending" {
		t.Fatalf("LLM status = %q, want pending", incident.LLMStatus)
	}
}

func TestCompressCollapsesRepeatedFileWrites(t *testing.T) {
	fixture, err := os.Open("../../testdata/events/web-download-execute-connect.json")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()

	normalizedEvents, err := events.LoadJSON(fixture)
	if err != nil {
		t.Fatal(err)
	}

	for index := range 3 {
		normalizedEvents = append(normalizedEvents, events.Event{
			EventID:           "evt-write-" + string(rune('1'+index)),
			Timestamp:         time.Date(2026, time.June, 2, 10, 15, 31, int(time.Duration(index+1)*100*time.Millisecond), time.UTC),
			Host:              "devbox-01",
			PID:               4120,
			PPID:              4112,
			UID:               33,
			ProcessName:       "curl",
			ParentProcessName: "sh",
			EventType:         events.TypeFileWrite,
			ExecutablePath:    "/usr/bin/curl",
			FilePath:          "/tmp/payload",
		})
	}

	detection := detect.NewBasic().Analyze(normalizedEvents)
	incident, err := compress.NewBasic().Compress(normalizedEvents, detection)
	if err != nil {
		t.Fatal(err)
	}

	const want = "curl wrote /tmp/payload 3 times"
	if !slices.Contains(incident.Timeline, want) {
		t.Fatalf("timeline = %v, want entry %q", incident.Timeline, want)
	}
	if len(incident.Timeline) != 6 {
		t.Fatalf("timeline entry count = %d, want 6", len(incident.Timeline))
	}
}

func TestCompressNarratesFailedMutationsAsFailures(t *testing.T) {
	timestamp := time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC)
	normalizedEvents := []events.Event{
		{
			EventID:     "evt-failed-write",
			Timestamp:   timestamp,
			Host:        "devbox-01",
			PID:         6001,
			ProcessName: "curl",
			EventType:   events.TypeFileWrite,
			FilePath:    "/tmp/payload",
			Metadata:    map[string]any{"outcome": "failed"},
		},
		{
			EventID:     "evt-failed-chmod",
			Timestamp:   timestamp.Add(time.Second),
			Host:        "devbox-01",
			PID:         6002,
			ProcessName: "chmod",
			EventType:   events.TypeChmod,
			FilePath:    "/tmp/payload",
			Metadata:    map[string]any{"outcome": "failed"},
		},
		{
			EventID:     "evt-empty-write",
			Timestamp:   timestamp.Add(2 * time.Second),
			Host:        "devbox-01",
			PID:         6001,
			ProcessName: "curl",
			EventType:   events.TypeFileWrite,
			FilePath:    "/tmp/payload",
			Metadata:    map[string]any{"outcome": "success", "written_bytes": int64(0)},
		},
	}

	incident, err := compress.NewBasic().Compress(normalizedEvents, detect.Result{})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"curl failed to write /tmp/payload",
		"chmod failed to make /tmp/payload executable",
		"curl completed zero-byte write to /tmp/payload",
	}
	if !slices.Equal(incident.Timeline, want) {
		t.Fatalf("timeline = %v, want %v", incident.Timeline, want)
	}
}

func TestCompressFormatsIPv6Endpoint(t *testing.T) {
	normalizedEvents := []events.Event{
		{
			EventID:        "evt-ipv6-connect",
			Timestamp:      time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC),
			Host:           "devbox-01",
			PID:            6001,
			ProcessName:    "payload",
			EventType:      events.TypeConnect,
			ExecutablePath: "/tmp/payload",
			RemoteAddr:     "2001:db8::5",
			RemotePort:     4444,
		},
	}

	incident, err := compress.NewBasic().Compress(normalizedEvents, detect.Result{})
	if err != nil {
		t.Fatal(err)
	}
	const want = "/tmp/payload connected to [2001:db8::5]:4444"
	if !slices.Contains(incident.Timeline, want) {
		t.Fatalf("timeline = %v, want entry %q", incident.Timeline, want)
	}
}

func TestCompressNarratesFailedConnect(t *testing.T) {
	normalizedEvents := []events.Event{
		{
			EventID:        "evt-failed-connect",
			Timestamp:      time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC),
			Host:           "devbox-01",
			PID:            6001,
			ProcessName:    "payload",
			EventType:      events.TypeConnect,
			ExecutablePath: "/tmp/payload",
			RemoteAddr:     "2001:db8::5",
			RemotePort:     4444,
			Metadata:       map[string]any{"outcome": "failed"},
		},
	}

	incident, err := compress.NewBasic().Compress(normalizedEvents, detect.Result{})
	if err != nil {
		t.Fatal(err)
	}
	const want = "/tmp/payload failed to connect to [2001:db8::5]:4444"
	if !slices.Contains(incident.Timeline, want) {
		t.Fatalf("timeline = %v, want entry %q", incident.Timeline, want)
	}
}

func TestCompressNarratesInProgressConnect(t *testing.T) {
	normalizedEvents := []events.Event{
		{
			EventID:        "evt-in-progress-connect",
			Timestamp:      time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC),
			Host:           "devbox-01",
			PID:            6001,
			ProcessName:    "payload",
			EventType:      events.TypeConnect,
			ExecutablePath: "/tmp/payload",
			RemoteAddr:     "2001:db8::5",
			RemotePort:     4444,
			Metadata:       map[string]any{"outcome": "in_progress"},
		},
	}

	incident, err := compress.NewBasic().Compress(normalizedEvents, detect.Result{})
	if err != nil {
		t.Fatal(err)
	}
	const want = "/tmp/payload started connecting to [2001:db8::5]:4444"
	if !slices.Contains(incident.Timeline, want) {
		t.Fatalf("timeline = %v, want entry %q", incident.Timeline, want)
	}
}
