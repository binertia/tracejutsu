package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"runtime-guard/internal/compress"
	"runtime-guard/internal/config"
	"runtime-guard/internal/detect"
	sensor "runtime-guard/internal/ebpf"
	"runtime-guard/internal/events"
	"runtime-guard/internal/llm"
	"runtime-guard/internal/persistqueue"
	"runtime-guard/internal/pipeline"
	"runtime-guard/internal/report"
	"runtime-guard/internal/store"
)

const (
	defaultFixture       = "testdata/events/web-download-execute-connect.json"
	defaultDB            = "runtime-guard.db"
	defaultStatsInterval = 10 * time.Second
)

var newLLMClient = func(config llm.HTTPConfig) (llm.Client, error) {
	return llm.NewHTTPClient(config)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", report.TerminalText(err.Error()))
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		writeUsage(out)
		return nil
	}

	switch args[0] {
	case "demo":
		return runDemo(args[1:], out)
	case "run":
		return runLive(args[1:], out)
	case "rules":
		for _, ruleID := range detect.RuleIDs() {
			fmt.Fprintln(out, ruleID)
		}
		return nil
	case "config":
		payload, err := json.MarshalIndent(config.Default(), "", "  ")
		if err != nil {
			return fmt.Errorf("encode config: %w", err)
		}
		fmt.Fprintln(out, string(payload))
		return nil
	case "events":
		return runEvents(args[1:], out)
	case "incidents":
		return runIncidents(args[1:], out)
	case "show":
		return runShow(args[1:], out)
	case "llm":
		return runLLM(args[1:], out)
	default:
		writeUsage(out)
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func runDemo(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", "", "persist results to a SQLite database")
	if err := flags.Parse(args); err != nil || len(flags.Args()) > 1 {
		return errors.New("usage: runtime-guard demo [--db path] [fixture.json]")
	}

	path := defaultFixture
	if len(flags.Args()) == 1 {
		path = flags.Args()[0]
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open fixture %q: %w", path, err)
	}
	defer file.Close()

	normalizedEvents, err := events.LoadJSON(file)
	if err != nil {
		return fmt.Errorf("load fixture %q: %w", path, err)
	}

	var database *store.SQLite
	if *databasePath != "" {
		database, err = store.OpenSQLite(*databasePath)
		if err != nil {
			return err
		}
		defer database.Close()
		if err := database.SaveEvents(context.Background(), normalizedEvents); err != nil {
			return err
		}
	}

	processor := newProcessor(pipeline.DefaultInactivityTimeout)
	reported := false
	for _, event := range normalizedEvents {
		analyses, err := processor.Add(event)
		if err != nil {
			return err
		}
		if err := writeAnalyses(context.Background(), out, database, analyses, &reported); err != nil {
			return err
		}
	}
	analyses, err := processor.Drain()
	if err != nil {
		return err
	}
	if err := writeAnalyses(context.Background(), out, database, analyses, &reported); err != nil {
		return err
	}

	if !reported {
		fmt.Fprintln(out, "no suspicious incidents")
	}
	if database != nil {
		fmt.Fprintf(out, "\nstored normalized events and incidents: %s\n", report.TerminalText(*databasePath))
	}
	return nil
}

func runLive(args []string, out io.Writer) (err error) {
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", "", "persist normalized events to a SQLite database")
	flushAfter := flags.Duration("flush-after", pipeline.DefaultInactivityTimeout, "flush inactive process trees after this duration")
	statsInterval := flags.Duration("stats-interval", defaultStatsInterval, "print runtime stats at this interval; 0 disables periodic stats")
	quietEvents := flags.Bool("quiet-events", false, "suppress per-event JSON output")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New("usage: runtime-guard run [--db path] [--flush-after duration] [--stats-interval duration] [--quiet-events]")
	}
	statsTicker, statsTicks, err := optionalTicker(*statsInterval)
	if err != nil {
		return err
	}
	if statsTicker != nil {
		defer statsTicker.Stop()
	}

	collector, err := sensor.NewRuntimeCollector()
	if err != nil {
		return fmt.Errorf("create runtime collector: %w", err)
	}

	var database *store.SQLite
	var eventQueue *persistqueue.Queue
	processor := newProcessor(*flushAfter)
	var normalizedEvents uint64
	if *databasePath != "" {
		database, err = store.OpenSQLite(*databasePath)
		if err != nil {
			return err
		}
		defer database.Close()
		eventQueue, err = persistqueue.New(database, persistqueue.DefaultCapacity)
		if err != nil {
			return err
		}
	}
	defer func() {
		if eventQueue != nil {
			closeErr := eventQueue.Close()
			if err == nil && closeErr != nil {
				err = closeErr
			}
		}
		writeLiveStats(out, collector, processor, eventQueue, normalizedEvents)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sink := make(chan events.Event, 1024)
	collectorErrors := make(chan error, 1)
	go func() {
		collectorErrors <- collector.Run(ctx, sink)
		close(sink)
	}()
	var eventQueueErrors <-chan error
	if eventQueue != nil {
		eventQueueErrors = eventQueue.Errors()
	}

	flushTicker := time.NewTicker(time.Second)
	defer flushTicker.Stop()

	fmt.Fprintf(out, "runtime-guard: collecting execve, IPv4/IPv6 connect, file write, and chmod events; quiet_events=%t stats_interval=%s; press Ctrl-C to stop\n",
		*quietEvents, statsIntervalLabel(*statsInterval))
	encoder := json.NewEncoder(out)
	for {
		select {
		case event, ok := <-sink:
			if !ok {
				analyses, err := processor.Drain()
				if err != nil {
					return err
				}
				reported := false
				if err := writeAnalyses(context.Background(), out, database, analyses, &reported); err != nil {
					return err
				}
				return <-collectorErrors
			}
			if eventQueue != nil {
				eventQueue.Enqueue(event)
			}
			normalizedEvents++
			if err := writeLiveEvent(encoder, event, *quietEvents); err != nil {
				return err
			}
			analyses, err := processor.Add(event)
			if err != nil {
				return err
			}
			reported := false
			if err := writeAnalyses(context.Background(), out, database, analyses, &reported); err != nil {
				return err
			}
		case now := <-flushTicker.C:
			analyses, err := processor.FlushInactive(now.UTC())
			if err != nil {
				return err
			}
			reported := false
			if err := writeAnalyses(context.Background(), out, database, analyses, &reported); err != nil {
				return err
			}
		case err := <-eventQueueErrors:
			return err
		case <-statsTicks:
			writeLiveStats(out, collector, processor, eventQueue, normalizedEvents)
		}
	}
}

func optionalTicker(interval time.Duration) (*time.Ticker, <-chan time.Time, error) {
	if interval < 0 {
		return nil, nil, errors.New("stats interval must be zero or positive")
	}
	if interval == 0 {
		return nil, nil, nil
	}
	ticker := time.NewTicker(interval)
	return ticker, ticker.C, nil
}

func statsIntervalLabel(interval time.Duration) string {
	if interval == 0 {
		return "disabled"
	}
	return interval.String()
}

func writeLiveEvent(encoder *json.Encoder, event events.Event, quiet bool) error {
	if quiet {
		return nil
	}
	if err := encoder.Encode(event); err != nil {
		return fmt.Errorf("write normalized event: %w", err)
	}
	return nil
}

func writeLiveStats(out io.Writer, collector sensor.Collector, processor *pipeline.Processor, eventQueue *persistqueue.Queue, normalizedEvents uint64) {
	pipelineStats := processor.Stats()
	var collectorStats sensor.Stats
	if provider, ok := collector.(sensor.StatsProvider); ok {
		collectorStats = provider.Stats()
	}
	var queueStats persistqueue.Stats
	if eventQueue != nil {
		queueStats = eventQueue.Stats()
	}
	fmt.Fprintf(out, "runtime stats: normalized=%d grouped=%d analyzed=%d incidents=%d ring_dropped=%d correlation_dropped=%d persist_received=%d persist_enqueued=%d persisted=%d persist_dropped=%d\n",
		normalizedEvents, pipelineStats.GroupedCandidates, pipelineStats.AnalyzedCandidates,
		pipelineStats.Incidents, collectorStats.RingBufferDropped, collectorStats.CorrelationDropped, queueStats.Received,
		queueStats.Enqueued, queueStats.Persisted, queueStats.Dropped)
}

func newProcessor(inactivityTimeout time.Duration) *pipeline.Processor {
	return pipeline.New(pipeline.Config{
		CorrelationWindow: events.DefaultCorrelationWindow,
		InactivityTimeout: inactivityTimeout,
		MaxCandidates:     pipeline.DefaultMaxCandidates,
		MaxEvents:         pipeline.DefaultMaxEvents,
		MaxRetainedEvents: pipeline.DefaultMaxRetainedEvents,
	}, detect.NewBasic(), compress.NewBasic())
}

func writeAnalyses(ctx context.Context, out io.Writer, database *store.SQLite, analyses []pipeline.Analysis, reported *bool) error {
	for _, analysis := range analyses {
		if database != nil {
			if err := database.SaveIncidentWithEvents(ctx, analysis.Incident, analysis.Events); err != nil {
				return err
			}
		}
		if *reported {
			fmt.Fprintln(out)
		}
		if err := report.Write(out, analysis.Incident); err != nil {
			return err
		}
		*reported = true
	}
	return nil
}

func runEvents(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("events", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", defaultDB, "SQLite database path")
	limit := flags.Int("limit", 50, "maximum events to print")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New("usage: runtime-guard events [--db path] [--limit count]")
	}

	database, err := store.OpenSQLite(*databasePath)
	if err != nil {
		return err
	}
	defer database.Close()

	normalizedEvents, err := database.ListEvents(context.Background(), *limit)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(out)
	for _, event := range normalizedEvents {
		if err := encoder.Encode(event); err != nil {
			return fmt.Errorf("write normalized event: %w", err)
		}
	}
	return nil
}

func runIncidents(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("incidents", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", defaultDB, "SQLite database path")
	limit := flags.Int("limit", 50, "maximum incidents to print")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New("usage: runtime-guard incidents [--db path] [--limit count]")
	}

	database, err := store.OpenSQLite(*databasePath)
	if err != nil {
		return err
	}
	defer database.Close()

	incidents, err := database.ListIncidents(context.Background(), *limit)
	if err != nil {
		return err
	}
	for _, incident := range incidents {
		fmt.Fprintf(out, "%s  %-8s score=%-3d  %s  %s\n",
			report.TerminalText(incident.IncidentID),
			detect.RiskLevel(incident.RiskScore),
			incident.RiskScore,
			incident.StartTime.UTC().Format("2006-01-02T15:04:05Z"),
			report.TerminalText(incident.Summary))
	}
	return nil
}

func runShow(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("show", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", defaultDB, "SQLite database path")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 1 {
		return errors.New("usage: runtime-guard show [--db path] <incident_id>")
	}

	database, err := store.OpenSQLite(*databasePath)
	if err != nil {
		return err
	}
	defer database.Close()

	incident, linkedEvents, err := database.GetIncident(context.Background(), flags.Args()[0])
	if err != nil {
		return err
	}
	if err := report.Write(out, incident); err != nil {
		return err
	}
	fmt.Fprintf(out, "\nEvidence events: %d\n", len(linkedEvents))
	llmReport, err := database.GetLLMReport(context.Background(), incident.IncidentID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(out)
	return report.WriteLLM(out, incident, llmReport.Report)
}

func runLLM(args []string, out io.Writer) error {
	defaults := config.Default()
	defaultTimeout, err := time.ParseDuration(defaults.LLM.Timeout)
	if err != nil {
		return fmt.Errorf("parse default LLM timeout: %w", err)
	}

	flags := flag.NewFlagSet("llm", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", defaultDB, "SQLite database path")
	endpoint := flags.String("endpoint", defaults.LLM.Endpoint, "llama-server-compatible HTTP endpoint")
	model := flags.String("model", defaults.LLM.Model, "local model identifier")
	timeout := flags.Duration("timeout", defaultTimeout, "LLM request timeout")
	remoteEndpointOptIn := flags.Bool("allow-remote-endpoint", defaults.LLM.RemoteEndpointOptIn, "allow a non-loopback LLM endpoint")
	preserveRawResponse := flags.Bool("preserve-raw-response", defaults.LLM.PreserveRawResponse, "store raw LLM output for debugging")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 1 {
		return errors.New("usage: runtime-guard llm [--db path] [--endpoint url] [--model name] [--timeout duration] [--allow-remote-endpoint] [--preserve-raw-response] <incident_id>")
	}

	database, err := store.OpenSQLite(*databasePath)
	if err != nil {
		return err
	}
	defer database.Close()

	incident, _, err := database.GetIncident(context.Background(), flags.Args()[0])
	if err != nil {
		return err
	}
	client, err := newLLMClient(llm.HTTPConfig{
		Endpoint:            *endpoint,
		Model:               *model,
		Timeout:             *timeout,
		RemoteEndpointOptIn: *remoteEndpointOptIn,
		PreserveRawResponse: *preserveRawResponse,
		APIKey:              os.Getenv("RUNTIME_GUARD_LLM_API_KEY"),
	})
	if err != nil {
		return err
	}
	analysis, err := client.Analyze(context.Background(), incident)
	if err != nil {
		return err
	}
	if err := database.SaveLLMReport(context.Background(), store.LLMReport{
		IncidentID:  incident.IncidentID,
		CreatedAt:   time.Now().UTC(),
		Model:       analysis.Model,
		Report:      analysis.Report,
		RawResponse: analysis.RawResponse,
	}); err != nil {
		return err
	}
	return report.WriteLLM(out, incident, analysis.Report)
}

func writeUsage(out io.Writer) {
	fmt.Fprintln(out, `runtime-guard: local-first runtime security analyst

Usage:
  runtime-guard demo [--db path] [fixture.json]       Run the fake-event incident pipeline
  runtime-guard run [--db path] [--flush-after time] [--stats-interval time] [--quiet-events]
                                                       Stream live runtime events and detect incidents (Linux amd64, root)
  runtime-guard events [--db path] [--limit count]    List stored normalized events
  runtime-guard incidents [--db path] [--limit count] List stored incidents
  runtime-guard show [--db path] <incident_id>        Show a stored incident
  runtime-guard llm [--db path] <incident_id>         Analyze a stored incident with a local LLM
  runtime-guard rules                List planned deterministic rules
  runtime-guard config               Print local-first default config`)
}
