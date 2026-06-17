package store

import (
	"context"
	"time"

	"tracejutsu/internal/compress"
	"tracejutsu/internal/events"
	"tracejutsu/internal/llm"
)

type LLMReport struct {
	IncidentID  string
	CreatedAt   time.Time
	Model       string
	Report      llm.Report
	RawResponse string
}

type EventProcessSummary struct {
	ProcessName    string
	ExecutablePath string
	Count          int64
}

type EventValueSummary struct {
	Value string
	Count int64
}

type TriageIncident struct {
	Incident      compress.Incident
	EvidenceCount int64
}

type SQLiteStats struct {
	JournalMode         string
	PageSize            int64
	PageCount           int64
	FreelistCount       int64
	EventCount          int64
	IncidentCount       int64
	IncidentEventCount  int64
	LLMReportCount      int64
	ApproxDatabaseBytes int64
}

// Store is intentionally small so SQLite can be added without coupling the
// event pipeline to database details.
type Store interface {
	SaveEvent(ctx context.Context, event events.Event) error
	SaveIncident(ctx context.Context, incident compress.Incident) error
	LinkIncidentEvents(ctx context.Context, incidentID string, eventIDs []string) error
	SaveIncidentWithEvents(ctx context.Context, incident compress.Incident, normalizedEvents []events.Event) error
	SaveLLMReport(ctx context.Context, report LLMReport) error
}
