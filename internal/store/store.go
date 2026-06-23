package store

import (
	"context"
	"time"

	"tracejutsu/internal/compress"
	"tracejutsu/internal/events"
	"tracejutsu/internal/llm"
)

type LLMReport struct {
	IncidentID  string     `json:"incident_id"`
	CreatedAt   time.Time  `json:"created_at"`
	Model       string     `json:"model"`
	Report      llm.Report `json:"report"`
	RawResponse string     `json:"raw_response,omitempty"`
}

type EventProcessSummary struct {
	ProcessName    string `json:"process_name"`
	ExecutablePath string `json:"executable_path"`
	Count          int64  `json:"count"`
}

type EventValueSummary struct {
	Value string `json:"value"`
	Count int64  `json:"count"`
}

type TriageIncident struct {
	Incident      compress.Incident `json:"incident"`
	EvidenceCount int64             `json:"evidence_count"`
}

type EventFilter struct {
	Limit       int
	EventType   string
	ProcessName string
	PID         int
	ContainerID string
	Since       time.Time
	Until       time.Time
}

type IncidentFilter struct {
	Limit     int
	MinScore  int
	LLMStatus string
	Since     time.Time
	Until     time.Time
}

type SQLiteStats struct {
	JournalMode         string `json:"journal_mode"`
	PageSize            int64  `json:"page_size"`
	PageCount           int64  `json:"page_count"`
	FreelistCount       int64  `json:"freelist_count"`
	EventCount          int64  `json:"events"`
	IncidentCount       int64  `json:"incidents"`
	IncidentEventCount  int64  `json:"incident_event_links"`
	LLMReportCount      int64  `json:"llm_reports"`
	ApproxDatabaseBytes int64  `json:"approx_database_bytes"`
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
