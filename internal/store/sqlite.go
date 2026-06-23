package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"tracejutsu/internal/compress"
	"tracejutsu/internal/events"
	"tracejutsu/internal/redact"
)

const defaultLimit = 50

type SQLite struct {
	db *sql.DB
}

func OpenSQLite(path string) (*SQLite, error) {
	if path == "" {
		return nil, errors.New("SQLite path is required")
	}
	if err := prepareSQLitePath(path); err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	db.SetMaxOpenConns(1)

	opened := &SQLite{db: db}
	if err := opened.initialize(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	if path != ":memory:" {
		if err := validateSQLiteFile(path); err != nil {
			db.Close()
			return nil, err
		}
	}
	return opened, nil
}

func (store *SQLite) initialize(ctx context.Context) error {
	for _, pragma := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
	} {
		if _, err := store.db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("initialize SQLite with %q: %w", pragma, err)
		}
	}
	if _, err := store.db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("apply SQLite schema: %w", err)
	}
	if err := ensureIncidentDroppedEventsColumn(ctx, store.db); err != nil {
		return err
	}
	return nil
}

func (store *SQLite) Close() error {
	return store.db.Close()
}

func (store *SQLite) JournalMode(ctx context.Context) (string, error) {
	var mode string
	if err := store.db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		return "", fmt.Errorf("read SQLite journal mode: %w", err)
	}
	return mode, nil
}

func (store *SQLite) Stats(ctx context.Context) (SQLiteStats, error) {
	journalMode, err := store.JournalMode(ctx)
	if err != nil {
		return SQLiteStats{}, err
	}
	pageSize, err := querySQLiteInt64(ctx, store.db, "PRAGMA page_size")
	if err != nil {
		return SQLiteStats{}, fmt.Errorf("read SQLite page size: %w", err)
	}
	pageCount, err := querySQLiteInt64(ctx, store.db, "PRAGMA page_count")
	if err != nil {
		return SQLiteStats{}, fmt.Errorf("read SQLite page count: %w", err)
	}
	freelistCount, err := querySQLiteInt64(ctx, store.db, "PRAGMA freelist_count")
	if err != nil {
		return SQLiteStats{}, fmt.Errorf("read SQLite freelist count: %w", err)
	}
	eventCount, err := querySQLiteInt64(ctx, store.db, "SELECT COUNT(*) FROM events")
	if err != nil {
		return SQLiteStats{}, fmt.Errorf("count events: %w", err)
	}
	incidentCount, err := querySQLiteInt64(ctx, store.db, "SELECT COUNT(*) FROM incidents")
	if err != nil {
		return SQLiteStats{}, fmt.Errorf("count incidents: %w", err)
	}
	incidentEventCount, err := querySQLiteInt64(ctx, store.db, "SELECT COUNT(*) FROM incident_events")
	if err != nil {
		return SQLiteStats{}, fmt.Errorf("count incident event links: %w", err)
	}
	llmReportCount, err := querySQLiteInt64(ctx, store.db, "SELECT COUNT(*) FROM llm_reports")
	if err != nil {
		return SQLiteStats{}, fmt.Errorf("count LLM reports: %w", err)
	}
	return SQLiteStats{
		JournalMode:         journalMode,
		PageSize:            pageSize,
		PageCount:           pageCount,
		FreelistCount:       freelistCount,
		EventCount:          eventCount,
		IncidentCount:       incidentCount,
		IncidentEventCount:  incidentEventCount,
		LLMReportCount:      llmReportCount,
		ApproxDatabaseBytes: pageSize * pageCount,
	}, nil
}

func querySQLiteInt64(ctx context.Context, db *sql.DB, query string) (int64, error) {
	var value int64
	if err := db.QueryRowContext(ctx, query).Scan(&value); err != nil {
		return 0, err
	}
	return value, nil
}

func (store *SQLite) SaveEvent(ctx context.Context, event events.Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("save event: %w", err)
	}
	if err := insertEvent(ctx, store.db, redact.Event(event)); err != nil {
		return fmt.Errorf("save event %q: %w", event.EventID, err)
	}
	return nil
}

func (store *SQLite) SaveEvents(ctx context.Context, normalizedEvents []events.Event) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin event batch: %w", err)
	}
	defer tx.Rollback()

	for _, event := range normalizedEvents {
		if err := event.Validate(); err != nil {
			return fmt.Errorf("save event %q: %w", event.EventID, err)
		}
		if err := insertEvent(ctx, tx, redact.Event(event)); err != nil {
			return fmt.Errorf("save event %q: %w", event.EventID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit event batch: %w", err)
	}
	return nil
}

func (store *SQLite) SaveIncident(ctx context.Context, incident compress.Incident) error {
	if err := validateIncident(incident); err != nil {
		return fmt.Errorf("save incident: %w", err)
	}
	if err := insertIncident(ctx, store.db, redact.Incident(incident)); err != nil {
		return fmt.Errorf("save incident %q: %w", incident.IncidentID, err)
	}
	return nil
}

func (store *SQLite) LinkIncidentEvents(ctx context.Context, incidentID string, eventIDs []string) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin incident event links: %w", err)
	}
	defer tx.Rollback()

	if err := replaceIncidentEventLinks(ctx, tx, incidentID, eventIDs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit incident event links: %w", err)
	}
	return nil
}

func (store *SQLite) SaveIncidentWithEvents(ctx context.Context, incident compress.Incident, normalizedEvents []events.Event) error {
	if err := validateIncident(incident); err != nil {
		return fmt.Errorf("save incident: %w", err)
	}

	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin incident batch: %w", err)
	}
	defer tx.Rollback()

	if err := insertIncident(ctx, tx, redact.Incident(incident)); err != nil {
		return fmt.Errorf("save incident %q: %w", incident.IncidentID, err)
	}
	eventIDs := make([]string, 0, len(normalizedEvents))
	for _, event := range normalizedEvents {
		if err := event.Validate(); err != nil {
			return fmt.Errorf("save incident event %q: %w", event.EventID, err)
		}
		if err := insertEvent(ctx, tx, redact.Event(event)); err != nil {
			return fmt.Errorf("save incident event %q: %w", event.EventID, err)
		}
		eventIDs = append(eventIDs, event.EventID)
	}
	if err := replaceIncidentEventLinks(ctx, tx, incident.IncidentID, eventIDs); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit incident batch: %w", err)
	}
	return nil
}

func (store *SQLite) ListEvents(ctx context.Context, limit int) ([]events.Event, error) {
	return store.ListEventsFiltered(ctx, EventFilter{Limit: limit})
}

func (store *SQLite) ListEventsFiltered(ctx context.Context, filter EventFilter) ([]events.Event, error) {
	query := `
SELECT event_id, timestamp, host, container_id, container_name, pid, ppid, uid,
       process_name, parent_process_name, event_type, executable_path,
       command_line_json, cwd, file_path, remote_addr, remote_port, metadata_json
FROM events
`
	clauses := make([]string, 0, 6)
	args := make([]any, 0, 7)
	if filter.EventType != "" {
		clauses = append(clauses, "event_type = ?")
		args = append(args, filter.EventType)
	}
	if filter.ProcessName != "" {
		clauses = append(clauses, "process_name = ?")
		args = append(args, filter.ProcessName)
	}
	if filter.PID > 0 {
		clauses = append(clauses, "pid = ?")
		args = append(args, filter.PID)
	}
	if filter.ContainerID != "" {
		clauses = append(clauses, "container_id = ?")
		args = append(args, filter.ContainerID)
	}
	if !filter.Since.IsZero() {
		clauses = append(clauses, "timestamp >= ?")
		args = append(args, formatTime(filter.Since))
	}
	if !filter.Until.IsZero() {
		clauses = append(clauses, "timestamp <= ?")
		args = append(args, formatTime(filter.Until))
	}
	if len(clauses) > 0 {
		query += "WHERE " + strings.Join(clauses, " AND ") + "\n"
	}
	query += "ORDER BY timestamp ASC, event_id ASC\nLIMIT ?"
	args = append(args, normalizeLimit(filter.Limit))

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	defer rows.Close()

	var loaded []events.Event
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}
	return loaded, nil
}

func (store *SQLite) TopEventProcesses(ctx context.Context, eventType string, limit int) ([]EventProcessSummary, error) {
	rows, err := store.db.QueryContext(ctx, `
SELECT process_name, executable_path, COUNT(*) AS event_count
FROM events
WHERE (? = '' OR event_type = ?)
GROUP BY process_name, executable_path
ORDER BY event_count DESC, process_name ASC, executable_path ASC
LIMIT ?`, eventType, eventType, normalizeLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("summarize event processes: %w", err)
	}
	defer rows.Close()

	var summaries []EventProcessSummary
	for rows.Next() {
		var summary EventProcessSummary
		if err := rows.Scan(&summary.ProcessName, &summary.ExecutablePath, &summary.Count); err != nil {
			return nil, fmt.Errorf("summarize event processes: %w", err)
		}
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("summarize event processes: %w", err)
	}
	return summaries, nil
}

func (store *SQLite) TopEventPaths(ctx context.Context, eventType string, limit int) ([]EventValueSummary, error) {
	rows, err := store.db.QueryContext(ctx, `
SELECT file_path, COUNT(*) AS event_count
FROM events
WHERE file_path <> '' AND (? = '' OR event_type = ?)
GROUP BY file_path
ORDER BY event_count DESC, file_path ASC
LIMIT ?`, eventType, eventType, normalizeLimit(limit))
	if err != nil {
		return nil, fmt.Errorf("summarize event paths: %w", err)
	}
	defer rows.Close()

	var summaries []EventValueSummary
	for rows.Next() {
		var summary EventValueSummary
		if err := rows.Scan(&summary.Value, &summary.Count); err != nil {
			return nil, fmt.Errorf("summarize event paths: %w", err)
		}
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("summarize event paths: %w", err)
	}
	return summaries, nil
}

func (store *SQLite) ListIncidents(ctx context.Context, limit int) ([]compress.Incident, error) {
	return store.ListIncidentsFiltered(ctx, IncidentFilter{Limit: limit})
}

func (store *SQLite) ListIncidentsFiltered(ctx context.Context, filter IncidentFilter) ([]compress.Incident, error) {
	query := `
SELECT incident_id, start_time, end_time, root_process_json, process_tree_json,
       risk_score, signals_json, timeline_json, summary, llm_status, dropped_events
FROM incidents
`
	clauses, args := incidentFilterClauses(filter)
	if len(clauses) > 0 {
		query += "WHERE " + strings.Join(clauses, " AND ") + "\n"
	}
	query += "ORDER BY start_time DESC, incident_id ASC\nLIMIT ?"
	args = append(args, normalizeLimit(filter.Limit))

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	defer rows.Close()

	var loaded []compress.Incident
	for rows.Next() {
		incident, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, incident)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list incidents: %w", err)
	}
	return loaded, nil
}

func (store *SQLite) ListTriageIncidents(ctx context.Context, limit int, minScore int) ([]TriageIncident, error) {
	return store.ListTriageIncidentsFiltered(ctx, IncidentFilter{Limit: limit, MinScore: minScore})
}

func (store *SQLite) ListTriageIncidentsFiltered(ctx context.Context, filter IncidentFilter) ([]TriageIncident, error) {
	query := `
SELECT i.incident_id, i.start_time, i.end_time, i.root_process_json, i.process_tree_json,
       i.risk_score, i.signals_json, i.timeline_json, i.summary, i.llm_status, i.dropped_events,
       COUNT(ie.event_id) AS evidence_count
FROM incidents i
LEFT JOIN incident_events ie ON ie.incident_id = i.incident_id
`
	clauses, args := incidentFilterClauses(filter)
	if len(clauses) > 0 {
		query += "WHERE " + strings.Join(prefixClauses("i.", clauses), " AND ") + "\n"
	}
	query += `
GROUP BY i.incident_id
ORDER BY i.risk_score DESC, i.start_time DESC, i.incident_id ASC
LIMIT ?`
	args = append(args, normalizeLimit(filter.Limit))

	rows, err := store.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list triage incidents: %w", err)
	}
	defer rows.Close()

	var loaded []TriageIncident
	for rows.Next() {
		entry, err := scanTriageIncident(rows)
		if err != nil {
			return nil, err
		}
		loaded = append(loaded, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list triage incidents: %w", err)
	}
	return loaded, nil
}

func incidentFilterClauses(filter IncidentFilter) ([]string, []any) {
	clauses := make([]string, 0, 4)
	args := make([]any, 0, 5)
	if filter.MinScore > 0 {
		clauses = append(clauses, "risk_score >= ?")
		args = append(args, filter.MinScore)
	}
	if filter.LLMStatus != "" {
		clauses = append(clauses, "llm_status = ?")
		args = append(args, filter.LLMStatus)
	}
	if !filter.Since.IsZero() {
		clauses = append(clauses, "start_time >= ?")
		args = append(args, formatTime(filter.Since))
	}
	if !filter.Until.IsZero() {
		clauses = append(clauses, "start_time <= ?")
		args = append(args, formatTime(filter.Until))
	}
	return clauses, args
}

func prefixClauses(prefix string, clauses []string) []string {
	prefixed := make([]string, 0, len(clauses))
	for _, clause := range clauses {
		switch {
		case strings.HasPrefix(clause, "risk_score"):
			prefixed = append(prefixed, prefix+clause)
		case strings.HasPrefix(clause, "llm_status"):
			prefixed = append(prefixed, prefix+clause)
		case strings.HasPrefix(clause, "start_time"):
			prefixed = append(prefixed, prefix+clause)
		default:
			prefixed = append(prefixed, clause)
		}
	}
	return prefixed
}

func (store *SQLite) GetIncident(ctx context.Context, incidentID string) (compress.Incident, []events.Event, error) {
	incident, err := scanIncident(store.db.QueryRowContext(ctx, `
SELECT incident_id, start_time, end_time, root_process_json, process_tree_json,
       risk_score, signals_json, timeline_json, summary, llm_status, dropped_events
FROM incidents
WHERE incident_id = ?`, incidentID))
	if err != nil {
		return compress.Incident{}, nil, err
	}

	rows, err := store.db.QueryContext(ctx, `
SELECT e.event_id, e.timestamp, e.host, e.container_id, e.container_name,
       e.pid, e.ppid, e.uid, e.process_name, e.parent_process_name,
       e.event_type, e.executable_path, e.command_line_json, e.cwd,
       e.file_path, e.remote_addr, e.remote_port, e.metadata_json
FROM events e
JOIN incident_events ie ON ie.event_id = e.event_id
WHERE ie.incident_id = ?
ORDER BY e.timestamp ASC, e.event_id ASC`, incidentID)
	if err != nil {
		return compress.Incident{}, nil, fmt.Errorf("list incident events %q: %w", incidentID, err)
	}
	defer rows.Close()

	var linkedEvents []events.Event
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return compress.Incident{}, nil, err
		}
		linkedEvents = append(linkedEvents, event)
	}
	if err := rows.Err(); err != nil {
		return compress.Incident{}, nil, fmt.Errorf("list incident events %q: %w", incidentID, err)
	}
	return incident, linkedEvents, nil
}

type executor interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

type scanner interface {
	Scan(dest ...any) error
}

func insertEvent(ctx context.Context, exec executor, event events.Event) error {
	commandLine, err := json.Marshal(event.CommandLine)
	if err != nil {
		return fmt.Errorf("encode command line: %w", err)
	}
	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("encode metadata: %w", err)
	}

	_, err = exec.ExecContext(ctx, `
INSERT INTO events (
    event_id, timestamp, host, container_id, container_name, pid, ppid, uid,
    process_name, parent_process_name, event_type, executable_path,
    command_line_json, cwd, file_path, remote_addr, remote_port, metadata_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(event_id) DO UPDATE SET
    timestamp = excluded.timestamp,
    host = excluded.host,
    container_id = excluded.container_id,
    container_name = excluded.container_name,
    pid = excluded.pid,
    ppid = excluded.ppid,
    uid = excluded.uid,
    process_name = excluded.process_name,
    parent_process_name = excluded.parent_process_name,
    event_type = excluded.event_type,
    executable_path = excluded.executable_path,
    command_line_json = excluded.command_line_json,
    cwd = excluded.cwd,
    file_path = excluded.file_path,
    remote_addr = excluded.remote_addr,
    remote_port = excluded.remote_port,
    metadata_json = excluded.metadata_json`,
		event.EventID, formatTime(event.Timestamp), event.Host, event.ContainerID,
		event.ContainerName, event.PID, event.PPID, event.UID, event.ProcessName,
		event.ParentProcessName, event.EventType, event.ExecutablePath, commandLine,
		event.CWD, event.FilePath, event.RemoteAddr, event.RemotePort, metadata)
	return err
}

func insertIncident(ctx context.Context, exec executor, incident compress.Incident) error {
	rootProcess, err := json.Marshal(incident.RootProcess)
	if err != nil {
		return fmt.Errorf("encode root process: %w", err)
	}
	processTree, err := json.Marshal(incident.ProcessTree)
	if err != nil {
		return fmt.Errorf("encode process tree: %w", err)
	}
	signals, err := json.Marshal(incident.Signals)
	if err != nil {
		return fmt.Errorf("encode signals: %w", err)
	}
	timeline, err := json.Marshal(incident.Timeline)
	if err != nil {
		return fmt.Errorf("encode timeline: %w", err)
	}

	_, err = exec.ExecContext(ctx, `
INSERT INTO incidents (
    incident_id, start_time, end_time, root_process_json, process_tree_json,
    risk_score, signals_json, timeline_json, summary, llm_status, dropped_events
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(incident_id) DO UPDATE SET
    start_time = excluded.start_time,
    end_time = excluded.end_time,
    root_process_json = excluded.root_process_json,
    process_tree_json = excluded.process_tree_json,
    risk_score = excluded.risk_score,
    signals_json = excluded.signals_json,
    timeline_json = excluded.timeline_json,
    summary = excluded.summary,
    llm_status = excluded.llm_status,
    dropped_events = excluded.dropped_events`,
		incident.IncidentID, formatTime(incident.StartTime), formatTime(incident.EndTime),
		rootProcess, processTree, incident.RiskScore, signals, timeline,
		incident.Summary, incident.LLMStatus, incident.DroppedEvents)
	return err
}

func replaceIncidentEventLinks(ctx context.Context, exec executor, incidentID string, eventIDs []string) error {
	if incidentID == "" {
		return errors.New("incident ID is required")
	}
	if _, err := exec.ExecContext(ctx, "DELETE FROM incident_events WHERE incident_id = ?", incidentID); err != nil {
		return fmt.Errorf("clear incident event links %q: %w", incidentID, err)
	}
	for _, eventID := range eventIDs {
		if _, err := exec.ExecContext(ctx,
			"INSERT INTO incident_events (incident_id, event_id) VALUES (?, ?)",
			incidentID, eventID); err != nil {
			return fmt.Errorf("link incident %q to event %q: %w", incidentID, eventID, err)
		}
	}
	return nil
}

func scanEvent(row scanner) (events.Event, error) {
	var event events.Event
	var timestamp string
	var commandLine []byte
	var metadata []byte
	if err := row.Scan(
		&event.EventID, &timestamp, &event.Host, &event.ContainerID,
		&event.ContainerName, &event.PID, &event.PPID, &event.UID,
		&event.ProcessName, &event.ParentProcessName, &event.EventType,
		&event.ExecutablePath, &commandLine, &event.CWD, &event.FilePath,
		&event.RemoteAddr, &event.RemotePort, &metadata,
	); err != nil {
		return event, fmt.Errorf("scan event: %w", err)
	}
	var err error
	event.Timestamp, err = parseTime(timestamp)
	if err != nil {
		return event, fmt.Errorf("parse event %q timestamp: %w", event.EventID, err)
	}
	if err := json.Unmarshal(commandLine, &event.CommandLine); err != nil {
		return event, fmt.Errorf("decode event %q command line: %w", event.EventID, err)
	}
	if err := json.Unmarshal(metadata, &event.Metadata); err != nil {
		return event, fmt.Errorf("decode event %q metadata: %w", event.EventID, err)
	}
	return event, nil
}

func scanIncident(row scanner) (compress.Incident, error) {
	var incident compress.Incident
	var startTime string
	var endTime string
	var rootProcess []byte
	var processTree []byte
	var signals []byte
	var timeline []byte
	if err := row.Scan(
		&incident.IncidentID, &startTime, &endTime, &rootProcess,
		&processTree, &incident.RiskScore, &signals, &timeline,
		&incident.Summary, &incident.LLMStatus, &incident.DroppedEvents,
	); err != nil {
		return incident, fmt.Errorf("scan incident: %w", err)
	}

	var err error
	incident.StartTime, err = parseTime(startTime)
	if err != nil {
		return incident, fmt.Errorf("parse incident %q start time: %w", incident.IncidentID, err)
	}
	incident.EndTime, err = parseTime(endTime)
	if err != nil {
		return incident, fmt.Errorf("parse incident %q end time: %w", incident.IncidentID, err)
	}
	if err := json.Unmarshal(rootProcess, &incident.RootProcess); err != nil {
		return incident, fmt.Errorf("decode incident %q root process: %w", incident.IncidentID, err)
	}
	if err := json.Unmarshal(processTree, &incident.ProcessTree); err != nil {
		return incident, fmt.Errorf("decode incident %q process tree: %w", incident.IncidentID, err)
	}
	if err := json.Unmarshal(signals, &incident.Signals); err != nil {
		return incident, fmt.Errorf("decode incident %q signals: %w", incident.IncidentID, err)
	}
	if err := json.Unmarshal(timeline, &incident.Timeline); err != nil {
		return incident, fmt.Errorf("decode incident %q timeline: %w", incident.IncidentID, err)
	}
	return incident, nil
}

func scanTriageIncident(row scanner) (TriageIncident, error) {
	var evidenceCount int64
	incident, err := scanIncident(scannerFunc(func(dest ...any) error {
		values := append(dest, &evidenceCount)
		return row.Scan(values...)
	}))
	if err != nil {
		return TriageIncident{}, err
	}
	return TriageIncident{
		Incident:      incident,
		EvidenceCount: evidenceCount,
	}, nil
}

type scannerFunc func(dest ...any) error

func (fn scannerFunc) Scan(dest ...any) error {
	return fn(dest...)
}

func validateIncident(incident compress.Incident) error {
	switch {
	case incident.IncidentID == "":
		return errors.New("incident_id is required")
	case incident.StartTime.IsZero():
		return errors.New("start_time is required")
	case incident.EndTime.IsZero():
		return errors.New("end_time is required")
	case incident.LLMStatus == "":
		return errors.New("llm_status is required")
	default:
		return nil
	}
}

func formatTime(timestamp time.Time) string {
	return timestamp.UTC().Format("2006-01-02T15:04:05.000000000Z")
}

func parseTime(timestamp string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, timestamp)
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return defaultLimit
	}
	return limit
}
