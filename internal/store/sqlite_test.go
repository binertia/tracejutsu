package store_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"tracejutsu/internal/compress"
	"tracejutsu/internal/detect"
	"tracejutsu/internal/events"
	"tracejutsu/internal/llm"
	"tracejutsu/internal/store"
)

func TestSQLitePersistsEventsAndIncidentLinks(t *testing.T) {
	ctx := context.Background()
	database := openTestSQLite(t)
	normalizedEvents := loadFixture(t, "../../testdata/events/web-download-execute-connect.json")

	reversed := append([]events.Event(nil), normalizedEvents...)
	slices.Reverse(reversed)
	if err := database.SaveEvents(ctx, reversed); err != nil {
		t.Fatal(err)
	}

	detection := detect.NewBasic().Analyze(normalizedEvents)
	incident, err := compress.NewBasic().Compress(normalizedEvents, detection)
	if err != nil {
		t.Fatal(err)
	}
	incident.DroppedEvents = 7
	if err := database.SaveIncidentWithEvents(ctx, incident, normalizedEvents); err != nil {
		t.Fatal(err)
	}

	storedEvents, err := database.ListEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	assertEventIDs(t, storedEvents, []string{"evt-001", "evt-002", "evt-003", "evt-004", "evt-005"})

	storedIncidents, err := database.ListIncidents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(storedIncidents) != 1 {
		t.Fatalf("incident count = %d, want 1", len(storedIncidents))
	}

	storedIncident, linkedEvents, err := database.GetIncident(ctx, incident.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if storedIncident.Summary != incident.Summary {
		t.Fatalf("summary = %q, want %q", storedIncident.Summary, incident.Summary)
	}
	if storedIncident.DroppedEvents != incident.DroppedEvents {
		t.Fatalf("dropped events = %d, want %d", storedIncident.DroppedEvents, incident.DroppedEvents)
	}
	assertEventIDs(t, linkedEvents, []string{"evt-001", "evt-002", "evt-003", "evt-004", "evt-005"})
}

func TestSQLiteIncidentBatchUpsertsEvidenceEvents(t *testing.T) {
	ctx := context.Background()
	database := openTestSQLite(t)
	normalizedEvents := loadFixture(t, "../../testdata/events/web-download-execute-connect.json")

	detection := detect.NewBasic().Analyze(normalizedEvents)
	incident, err := compress.NewBasic().Compress(normalizedEvents, detection)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveIncidentWithEvents(ctx, incident, normalizedEvents); err != nil {
		t.Fatal(err)
	}

	storedEvents, err := database.ListEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	assertEventIDs(t, storedEvents, []string{"evt-001", "evt-002", "evt-003", "evt-004", "evt-005"})

	_, linkedEvents, err := database.GetIncident(ctx, incident.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	assertEventIDs(t, linkedEvents, []string{"evt-001", "evt-002", "evt-003", "evt-004", "evt-005"})
}

func TestSQLiteUsesWALMode(t *testing.T) {
	database := openTestSQLite(t)
	mode, err := database.JournalMode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if mode != "wal" {
		t.Fatalf("journal mode = %q, want wal", mode)
	}
}

func TestSQLiteStats(t *testing.T) {
	ctx := context.Background()
	database := openTestSQLite(t)
	normalizedEvents := loadFixture(t, "../../testdata/events/web-download-execute-connect.json")
	if err := database.SaveEvents(ctx, normalizedEvents); err != nil {
		t.Fatal(err)
	}
	detection := detect.NewBasic().Analyze(normalizedEvents)
	incident, err := compress.NewBasic().Compress(normalizedEvents, detection)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveIncidentWithEvents(ctx, incident, normalizedEvents); err != nil {
		t.Fatal(err)
	}

	stats, err := database.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stats.JournalMode != "wal" {
		t.Fatalf("journal mode = %q, want wal", stats.JournalMode)
	}
	if stats.EventCount != int64(len(normalizedEvents)) {
		t.Fatalf("event count = %d, want %d", stats.EventCount, len(normalizedEvents))
	}
	if stats.IncidentCount != 1 {
		t.Fatalf("incident count = %d, want 1", stats.IncidentCount)
	}
	if stats.IncidentEventCount != int64(len(normalizedEvents)) {
		t.Fatalf("incident event count = %d, want %d", stats.IncidentEventCount, len(normalizedEvents))
	}
	if stats.PageSize <= 0 || stats.PageCount <= 0 || stats.ApproxDatabaseBytes <= 0 {
		t.Fatalf("unexpected size stats: %#v", stats)
	}
}

func TestSQLiteRedactsPersistedEventsAndIncidents(t *testing.T) {
	ctx := context.Background()
	database := openTestSQLite(t)

	event := events.Event{
		EventID:        "evt-secret",
		Timestamp:      time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC),
		Host:           "devbox-01",
		PID:            100,
		ProcessName:    "curl",
		EventType:      events.TypeExecve,
		ExecutablePath: "/usr/bin/curl",
		CommandLine:    []string{"curl", "https://example.com/?token=abc123", "--password=supersecret"},
		Metadata: map[string]any{
			"api_key": "secret",
		},
	}
	if err := database.SaveEvent(ctx, event); err != nil {
		t.Fatal(err)
	}
	storedEvents, err := database.ListEvents(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(storedEvents) != 1 {
		t.Fatalf("event count = %d, want 1", len(storedEvents))
	}
	if strings.Contains(strings.Join(storedEvents[0].CommandLine, " "), "abc123") || strings.Contains(strings.Join(storedEvents[0].CommandLine, " "), "supersecret") {
		t.Fatalf("stored event command line leaked secret: %#v", storedEvents[0].CommandLine)
	}
	if storedEvents[0].Metadata["api_key"] != "[REDACTED]" {
		t.Fatalf("stored metadata = %#v, want [REDACTED]", storedEvents[0].Metadata["api_key"])
	}

	incident := compress.Incident{
		IncidentID: "inc-secret",
		StartTime:  time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC),
		EndTime:    time.Date(2026, time.June, 2, 12, 1, 0, 0, time.UTC),
		RootProcess: compress.RootProcess{
			PID:            100,
			ProcessName:    "curl",
			ExecutablePath: "/usr/bin/curl?token=abc123",
		},
		ProcessTree: []string{"curl -> sh token=abc123"},
		Timeline:    []string{"curl fetched https://example.com/?password=supersecret"},
		Summary:     "secret=abc123",
		LLMStatus:   "pending",
	}
	if err := database.SaveIncident(ctx, incident); err != nil {
		t.Fatal(err)
	}
	storedIncident, _, err := database.GetIncident(ctx, incident.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedIncident.Summary, "abc123") {
		t.Fatalf("stored incident summary leaked secret: %q", storedIncident.Summary)
	}
	if strings.Contains(strings.Join(storedIncident.Timeline, " "), "supersecret") {
		t.Fatalf("stored incident timeline leaked secret: %v", storedIncident.Timeline)
	}
}

func TestOpenSQLiteCreatesPrivateDatabaseFile(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "tracejutsu.db")
	database, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, privatePath := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(privatePath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got&0o077 != 0 {
			t.Fatalf("%s permissions = %04o, want no group or other access", privatePath, got)
		}
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenSQLiteRejectsPermissiveExistingDatabaseFile(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "tracejutsu.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := store.OpenSQLite(path); err == nil {
		t.Fatal("expected permissive database file rejection")
	}
}

func TestOpenSQLiteRejectsWritableParentDirectory(t *testing.T) {
	parent := filepath.Join(privateTempDir(t), "shared")
	if err := os.Mkdir(parent, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}

	if _, err := store.OpenSQLite(filepath.Join(parent, "tracejutsu.db")); err == nil {
		t.Fatal("expected writable parent directory rejection")
	}
}

func TestOpenSQLiteRejectsSymlinkDatabasePath(t *testing.T) {
	directory := privateTempDir(t)
	target := filepath.Join(directory, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "tracejutsu.db")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	if _, err := store.OpenSQLite(path); err == nil {
		t.Fatal("expected symlink database path rejection")
	}
}

func TestOpenSQLiteRejectsPermissiveExistingSidecar(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "tracejutsu.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sidecar := path + "-wal"
	if err := os.WriteFile(sidecar, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sidecar, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := store.OpenSQLite(path); err == nil {
		t.Fatal("expected permissive SQLite sidecar rejection")
	}
}

func TestOpenSQLiteRejectsSymlinkSidecar(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "tracejutsu.db")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(directory, "sidecar-target")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path+"-shm"); err != nil {
		t.Fatal(err)
	}

	if _, err := store.OpenSQLite(path); err == nil {
		t.Fatal("expected symlink SQLite sidecar rejection")
	}
}

func TestOpenSQLiteRejectsOrphanedSidecar(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "tracejutsu.db")
	if err := os.WriteFile(path+"-wal", nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.OpenSQLite(path); err == nil {
		t.Fatal("expected orphaned SQLite sidecar rejection")
	}
}

func TestOpenSQLiteUpgradesLegacyIncidentSchema(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "tracejutsu.db")
	database, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`
CREATE TABLE incidents (
    incident_id TEXT PRIMARY KEY,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    root_process_json TEXT NOT NULL,
    process_tree_json TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    signals_json TEXT NOT NULL,
    timeline_json TEXT NOT NULL,
    summary TEXT NOT NULL,
    llm_status TEXT NOT NULL
)`); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	upgraded, err := store.OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer upgraded.Close()

	incident := compress.Incident{
		IncidentID:    "inc-legacy",
		StartTime:     time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC),
		EndTime:       time.Date(2026, time.June, 2, 12, 0, 1, 0, time.UTC),
		LLMStatus:     "pending",
		DroppedEvents: 3,
	}
	if err := upgraded.SaveIncident(context.Background(), incident); err != nil {
		t.Fatal(err)
	}
	stored, _, err := upgraded.GetIncident(context.Background(), incident.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.DroppedEvents != incident.DroppedEvents {
		t.Fatalf("dropped events = %d, want %d", stored.DroppedEvents, incident.DroppedEvents)
	}
}

func TestSQLiteOrdersFractionalTimestamps(t *testing.T) {
	ctx := context.Background()
	database := openTestSQLite(t)
	normalizedEvents := loadFixture(t, "../../testdata/events/mixed-process-trees.json")
	if err := database.SaveEvents(ctx, normalizedEvents); err != nil {
		t.Fatal(err)
	}

	storedEvents, err := database.ListEvents(ctx, 100)
	if err != nil {
		t.Fatal(err)
	}
	assertEventIDs(t, storedEvents, []string{
		"evt-001",
		"evt-noise-001",
		"evt-002",
		"evt-noise-002",
		"evt-003",
		"evt-004",
		"evt-005",
	})
}

func TestSQLiteRejectsMissingIncidentEvent(t *testing.T) {
	ctx := context.Background()
	database := openTestSQLite(t)
	normalizedEvents := loadFixture(t, "../../testdata/events/web-download-execute-connect.json")

	detection := detect.NewBasic().Analyze(normalizedEvents)
	incident, err := compress.NewBasic().Compress(normalizedEvents, detection)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveIncident(ctx, incident); err != nil {
		t.Fatal(err)
	}
	if err := database.LinkIncidentEvents(ctx, incident.IncidentID, []string{"missing-event"}); err == nil {
		t.Fatal("expected foreign key error for a missing event")
	}
}

func TestSQLitePersistsLLMReportAndMarksIncidentComplete(t *testing.T) {
	ctx := context.Background()
	database := openTestSQLite(t)
	normalizedEvents := loadFixture(t, "../../testdata/events/web-download-execute-connect.json")
	detection := detect.NewBasic().Analyze(normalizedEvents)
	incident, err := compress.NewBasic().Compress(normalizedEvents, detection)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.SaveEvents(ctx, normalizedEvents); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveIncidentWithEvents(ctx, incident, normalizedEvents); err != nil {
		t.Fatal(err)
	}

	createdAt := time.Date(2026, time.June, 2, 12, 0, 0, 0, time.UTC)
	expected := store.LLMReport{
		IncidentID: incident.IncidentID,
		CreatedAt:  createdAt,
		Model:      "test-model",
		Report: llm.Report{
			Summary:                    "Suspicious runtime chain.",
			RiskLevel:                  "critical",
			LikelyBehavior:             "Possible payload execution.",
			WhySuspicious:              []string{"Downloaded binary connected outbound."},
			FalsePositivePossibilities: []string{"Administrative test."},
			RecommendedCommands:        []string{"ps -fp 4131"},
			ContainmentAdvice:          []string{"Review manually."},
		},
		RawResponse: `{"debug":"preserved"}`,
	}
	if err := database.SaveLLMReport(ctx, expected); err != nil {
		t.Fatal(err)
	}

	stored, err := database.GetLLMReport(ctx, incident.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Model != expected.Model || stored.RawResponse != expected.RawResponse {
		t.Fatalf("stored LLM metadata = %+v, want %+v", stored, expected)
	}
	if stored.Report.Summary != expected.Report.Summary {
		t.Fatalf("stored LLM summary = %q, want %q", stored.Report.Summary, expected.Report.Summary)
	}

	storedIncident, _, err := database.GetIncident(ctx, incident.IncidentID)
	if err != nil {
		t.Fatal(err)
	}
	if storedIncident.LLMStatus != "complete" {
		t.Fatalf("LLM status = %q, want complete", storedIncident.LLMStatus)
	}
}

func TestSQLiteListTriageIncidentsOrdersFiltersAndCountsEvidence(t *testing.T) {
	ctx := context.Background()
	database := openTestSQLite(t)
	normalizedEvents := loadFixture(t, "../../testdata/events/web-download-execute-connect.json")
	if err := database.SaveEvents(ctx, normalizedEvents); err != nil {
		t.Fatal(err)
	}

	for _, incident := range []compress.Incident{
		testIncident("inc-low", 20, time.Date(2026, time.June, 3, 10, 0, 0, 0, time.UTC)),
		testIncident("inc-critical-old", 90, time.Date(2026, time.June, 3, 11, 0, 0, 0, time.UTC)),
		testIncident("inc-critical-new", 90, time.Date(2026, time.June, 3, 12, 0, 0, 0, time.UTC)),
		testIncident("inc-high", 70, time.Date(2026, time.June, 3, 13, 0, 0, 0, time.UTC)),
	} {
		if err := database.SaveIncident(ctx, incident); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.LinkIncidentEvents(ctx, "inc-critical-new", []string{"evt-001", "evt-002"}); err != nil {
		t.Fatal(err)
	}
	if err := database.LinkIncidentEvents(ctx, "inc-critical-old", []string{"evt-003"}); err != nil {
		t.Fatal(err)
	}
	if err := database.LinkIncidentEvents(ctx, "inc-high", []string{"evt-004", "evt-005"}); err != nil {
		t.Fatal(err)
	}

	entries, err := database.ListTriageIncidents(ctx, 2, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("entry count = %d, want 2", len(entries))
	}
	if entries[0].Incident.IncidentID != "inc-critical-new" || entries[0].EvidenceCount != 2 {
		t.Fatalf("first entry = %+v, want inc-critical-new with 2 evidence events", entries[0])
	}
	if entries[1].Incident.IncidentID != "inc-critical-old" || entries[1].EvidenceCount != 1 {
		t.Fatalf("second entry = %+v, want inc-critical-old with 1 evidence event", entries[1])
	}
}

func testIncident(id string, score int, start time.Time) compress.Incident {
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
		Summary:   "test summary",
		LLMStatus: "pending",
	}
}

func openTestSQLite(t *testing.T) *store.SQLite {
	t.Helper()
	database, err := store.OpenSQLite(filepath.Join(privateTempDir(t), "tracejutsu.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Error(err)
		}
	})
	return database
}

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
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

func assertEventIDs(t *testing.T, actual []events.Event, expected []string) {
	t.Helper()
	if len(actual) != len(expected) {
		t.Fatalf("event count = %d, want %d", len(actual), len(expected))
	}
	for index, event := range actual {
		if event.EventID != expected[index] {
			t.Fatalf("event %d ID = %q, want %q", index, event.EventID, expected[index])
		}
	}
}
