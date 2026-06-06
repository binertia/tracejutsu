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
	"strings"
	"syscall"
	"time"

	"tracejutsu/internal/compress"
	"tracejutsu/internal/config"
	"tracejutsu/internal/detect"
	sensor "tracejutsu/internal/ebpf"
	"tracejutsu/internal/events"
	"tracejutsu/internal/llm"
	"tracejutsu/internal/persistqueue"
	"tracejutsu/internal/pipeline"
	"tracejutsu/internal/report"
	"tracejutsu/internal/store"
)

const (
	defaultFixture         = "testdata/events/web-download-execute-connect.json"
	defaultDB              = "tracejutsu.db"
	defaultStatsInterval   = 10 * time.Second
	defaultLiveEventBuffer = 8192
)

var (
	buildVersion = "dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
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
	case "version":
		return runVersion(args[1:], out)
	case "events":
		return runEvents(args[1:], out)
	case "event-summary":
		return runEventSummary(args[1:], out)
	case "db-stats":
		return runDBStats(args[1:], out)
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

func runVersion(args []string, out io.Writer) error {
	if len(args) != 0 {
		return errors.New("usage: tracejutsu version")
	}
	fmt.Fprintf(out, "tracejutsu %s\n", report.TerminalText(buildVersion))
	fmt.Fprintf(out, "commit: %s\n", report.TerminalText(buildCommit))
	fmt.Fprintf(out, "build_date: %s\n", report.TerminalText(buildDate))
	return nil
}

func runDemo(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("demo", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", "", "persist results to a SQLite database")
	if err := flags.Parse(args); err != nil || len(flags.Args()) > 1 {
		return errors.New("usage: tracejutsu demo [--db path] [fixture.json]")
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
		if err := writeAnalyses(context.Background(), out, database, nil, analyses, &reported); err != nil {
			return err
		}
	}
	analyses, err := processor.Drain()
	if err != nil {
		return err
	}
	if err := writeAnalyses(context.Background(), out, database, nil, analyses, &reported); err != nil {
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
	eventBuffer := flags.Int("event-buffer", defaultLiveEventBuffer, "collector-to-analyzer event channel capacity")
	persistBuffer := flags.Int("persist-buffer", persistqueue.DefaultCapacity, "async event persistence queue capacity")
	persistBatchSize := flags.Int("persist-batch-size", persistqueue.DefaultBatchSize, "maximum normalized events per async persistence transaction")
	ringBufferSize := flags.Int("ring-buffer-size", sensor.DefaultRingBufferSize, "per-collector eBPF ring buffer size in bytes; must be a power of two")
	collectorNames := flags.String("collectors", strings.Join(sensor.DefaultCollectorNames(), ","), "comma-separated collectors to enable: all, behavior_core, execve, connect, file_write, chmod, sensitive_read, file_lifecycle, privilege_change, namespace_change, process_access, network_server, kernel_tamper")
	fileWriteMinBytes := flags.Int64("file-write-min-bytes", 0, "minimum successful bytes for file_write events; 0 captures all completed writes")
	quietEvents := flags.Bool("quiet-events", false, "suppress per-event JSON output")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New("usage: tracejutsu run [--db path] [--flush-after duration] [--stats-interval duration] [--event-buffer count] [--persist-buffer count] [--persist-batch-size count] [--ring-buffer-size bytes] [--collectors list] [--file-write-min-bytes bytes] [--quiet-events]")
	}
	if *eventBuffer <= 0 {
		return errors.New("event buffer size must be positive")
	}
	if *persistBuffer <= 0 {
		return errors.New("persist buffer size must be positive")
	}
	if *persistBatchSize <= 0 {
		return errors.New("persist batch size must be positive")
	}
	if *ringBufferSize <= 0 {
		return errors.New("ring buffer size must be positive")
	}
	enabledCollectors, err := sensor.ParseCollectorNames(*collectorNames)
	if err != nil {
		return err
	}
	statsTicker, statsTicks, err := optionalTicker(*statsInterval)
	if err != nil {
		return err
	}
	if statsTicker != nil {
		defer statsTicker.Stop()
	}

	collector, err := sensor.NewRuntimeCollectorWithConfig(sensor.RuntimeConfig{
		RingBufferSize:     *ringBufferSize,
		Collectors:         enabledCollectors,
		FileWriteMinBytes:  *fileWriteMinBytes,
		FileWriteIgnorePID: os.Getpid(),
	})
	if err != nil {
		return fmt.Errorf("create runtime collector: %w", err)
	}

	var database *store.SQLite
	var eventQueue *persistqueue.Queue
	var incidentQueue *persistqueue.IncidentQueue
	processor := newProcessor(*flushAfter)
	var normalizedEvents uint64
	if *databasePath != "" {
		database, err = store.OpenSQLite(*databasePath)
		if err != nil {
			return err
		}
		defer database.Close()
		eventQueue, err = persistqueue.NewWithConfig(database, persistqueue.Config{
			Capacity:  *persistBuffer,
			BatchSize: *persistBatchSize,
		})
		if err != nil {
			return err
		}
		incidentQueue, err = persistqueue.NewIncidentQueueWithConfig(database, persistqueue.Config{
			Capacity: *persistBuffer,
		})
		if err != nil {
			return err
		}
	}
	defer func() {
		if incidentQueue != nil {
			closeErr := incidentQueue.Close()
			if err == nil && closeErr != nil {
				err = closeErr
			}
		}
		if eventQueue != nil {
			closeErr := eventQueue.Close()
			if err == nil && closeErr != nil {
				err = closeErr
			}
		}
		writeLiveStats(out, collector, processor, eventQueue, incidentQueue, normalizedEvents)
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	sink := make(chan events.Event, *eventBuffer)
	collectorErrors := make(chan error, 1)
	go func() {
		collectorErrors <- collector.Run(ctx, sink)
		close(sink)
	}()
	var eventQueueErrors <-chan error
	if eventQueue != nil {
		eventQueueErrors = eventQueue.Errors()
	}
	var incidentQueueErrors <-chan error
	if incidentQueue != nil {
		incidentQueueErrors = incidentQueue.Errors()
	}

	flushTicker := time.NewTicker(time.Second)
	defer flushTicker.Stop()

	fmt.Fprintf(out, "tracejutsu: collecting %s events; quiet_events=%t stats_interval=%s event_buffer=%d persist_buffer=%d persist_batch_size=%d ring_buffer_size=%d file_write_min_bytes=%d file_write_ignore_pid=%d; press Ctrl-C to stop\n",
		strings.Join(enabledCollectors, ","), *quietEvents, statsIntervalLabel(*statsInterval), *eventBuffer, *persistBuffer, *persistBatchSize, *ringBufferSize, *fileWriteMinBytes, os.Getpid())
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
				if err := writeAnalyses(context.Background(), out, database, incidentQueue, analyses, &reported); err != nil {
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
			if err := writeAnalyses(context.Background(), out, database, incidentQueue, analyses, &reported); err != nil {
				return err
			}
		case now := <-flushTicker.C:
			analyses, err := processor.FlushInactive(now.UTC())
			if err != nil {
				return err
			}
			reported := false
			if err := writeAnalyses(context.Background(), out, database, incidentQueue, analyses, &reported); err != nil {
				return err
			}
		case err := <-eventQueueErrors:
			return err
		case err := <-incidentQueueErrors:
			return err
		case <-statsTicks:
			writeLiveStats(out, collector, processor, eventQueue, incidentQueue, normalizedEvents)
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

func writeLiveStats(out io.Writer, collector sensor.Collector, processor *pipeline.Processor, eventQueue *persistqueue.Queue, incidentQueue *persistqueue.IncidentQueue, normalizedEvents uint64) {
	pipelineStats := processor.Stats()
	var collectorStats sensor.Stats
	if provider, ok := collector.(sensor.StatsProvider); ok {
		collectorStats = provider.Stats()
	}
	var queueStats persistqueue.Stats
	if eventQueue != nil {
		queueStats = eventQueue.Stats()
	}
	var incidentQueueStats persistqueue.Stats
	if incidentQueue != nil {
		incidentQueueStats = incidentQueue.Stats()
	}
	fmt.Fprintf(out, "runtime stats: normalized=%d grouped=%d analyzed=%d incidents=%d ring_dropped=%d correlation_dropped=%d persist_received=%d persist_enqueued=%d persisted=%d persist_dropped=%d incident_persist_received=%d incident_persist_enqueued=%d incident_persisted=%d incident_persist_dropped=%d",
		normalizedEvents, pipelineStats.GroupedCandidates, pipelineStats.AnalyzedCandidates,
		pipelineStats.Incidents, collectorStats.RingBufferDropped, collectorStats.CorrelationDropped, queueStats.Received,
		queueStats.Enqueued, queueStats.Persisted, queueStats.Dropped, incidentQueueStats.Received,
		incidentQueueStats.Enqueued, incidentQueueStats.Persisted, incidentQueueStats.Dropped)
	if detailProvider, ok := collector.(sensor.StatsDetailProvider); ok {
		details := detailProvider.StatsByCollector()
		fmt.Fprintf(out, " collector_ring_dropped=%s collector_correlation_dropped=%s",
			collectorStatsLabel(details, func(stats sensor.Stats) uint64 {
				return stats.RingBufferDropped
			}),
			collectorStatsLabel(details, func(stats sensor.Stats) uint64 {
				return stats.CorrelationDropped
			}))
	}
	fmt.Fprintln(out)
}

func collectorStatsLabel(details []sensor.CollectorStats, value func(sensor.Stats) uint64) string {
	if len(details) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(details))
	for _, detail := range details {
		parts = append(parts, fmt.Sprintf("%s:%d", detail.Name, value(detail.Stats)))
	}
	return strings.Join(parts, ",")
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

func writeAnalyses(ctx context.Context, out io.Writer, database *store.SQLite, incidentQueue *persistqueue.IncidentQueue, analyses []pipeline.Analysis, reported *bool) error {
	for _, analysis := range analyses {
		if database != nil {
			if incidentQueue != nil {
				incidentQueue.Enqueue(persistqueue.IncidentRecord{
					Incident: analysis.Incident,
					Events:   analysis.Events,
				})
			} else {
				if err := database.SaveIncidentWithEvents(ctx, analysis.Incident, analysis.Events); err != nil {
					return err
				}
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

func openExistingSQLite(path string) (*store.SQLite, error) {
	if path != ":memory:" {
		if _, err := os.Lstat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("SQLite database does not exist: %q", path)
			}
			return nil, fmt.Errorf("inspect SQLite database path: %w", err)
		}
	}
	return store.OpenSQLite(path)
}

func runEvents(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("events", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", defaultDB, "SQLite database path")
	limit := flags.Int("limit", 50, "maximum events to print")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New("usage: tracejutsu events [--db path] [--limit count]")
	}

	database, err := openExistingSQLite(*databasePath)
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

func runEventSummary(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("event-summary", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", defaultDB, "SQLite database path")
	eventType := flags.String("type", "", "event type to summarize, for example file_write")
	limit := flags.Int("limit", 10, "maximum rows per summary section")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New("usage: tracejutsu event-summary [--db path] [--type event_type] [--limit count]")
	}

	database, err := openExistingSQLite(*databasePath)
	if err != nil {
		return err
	}
	defer database.Close()

	processes, err := database.TopEventProcesses(context.Background(), *eventType, *limit)
	if err != nil {
		return err
	}
	paths, err := database.TopEventPaths(context.Background(), *eventType, *limit)
	if err != nil {
		return err
	}

	if *eventType == "" {
		fmt.Fprintln(out, "event summary")
	} else {
		fmt.Fprintf(out, "event summary: type=%s\n", report.TerminalText(*eventType))
	}
	fmt.Fprintln(out, "\nTop processes:")
	if len(processes) == 0 {
		fmt.Fprintln(out, "  none")
	} else {
		for _, process := range processes {
			executablePath := report.TerminalText(process.ExecutablePath)
			if executablePath == "" {
				executablePath = "-"
			}
			fmt.Fprintf(out, "  %8d  %-24s  %s\n",
				process.Count, report.TerminalText(process.ProcessName), executablePath)
		}
	}

	fmt.Fprintln(out, "\nTop file paths:")
	if len(paths) == 0 {
		fmt.Fprintln(out, "  none")
	} else {
		for _, path := range paths {
			fmt.Fprintf(out, "  %8d  %s\n", path.Count, report.TerminalText(path.Value))
		}
	}
	return nil
}

func runDBStats(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("db-stats", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", defaultDB, "SQLite database path")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New("usage: tracejutsu db-stats [--db path]")
	}
	if *databasePath == ":memory:" {
		return errors.New("db-stats requires a filesystem SQLite database")
	}

	database, err := openExistingSQLite(*databasePath)
	if err != nil {
		return err
	}
	defer database.Close()

	stats, err := database.Stats(context.Background())
	if err != nil {
		return err
	}
	databaseBytes, err := regularFileSize(*databasePath)
	if err != nil {
		return err
	}
	walBytes, err := optionalRegularFileSize(*databasePath + "-wal")
	if err != nil {
		return err
	}
	shmBytes, err := optionalRegularFileSize(*databasePath + "-shm")
	if err != nil {
		return err
	}

	fmt.Fprintln(out, "database stats")
	fmt.Fprintf(out, "path: %s\n", report.TerminalText(*databasePath))
	fmt.Fprintf(out, "journal_mode: %s\n", report.TerminalText(stats.JournalMode))
	fmt.Fprintf(out, "database_bytes: %d\n", databaseBytes)
	fmt.Fprintf(out, "wal_bytes: %d\n", walBytes)
	fmt.Fprintf(out, "shm_bytes: %d\n", shmBytes)
	fmt.Fprintf(out, "page_size: %d\n", stats.PageSize)
	fmt.Fprintf(out, "page_count: %d\n", stats.PageCount)
	fmt.Fprintf(out, "freelist_count: %d\n", stats.FreelistCount)
	fmt.Fprintf(out, "approx_database_bytes: %d\n", stats.ApproxDatabaseBytes)
	fmt.Fprintf(out, "events: %d\n", stats.EventCount)
	fmt.Fprintf(out, "incidents: %d\n", stats.IncidentCount)
	fmt.Fprintf(out, "incident_event_links: %d\n", stats.IncidentEventCount)
	fmt.Fprintf(out, "llm_reports: %d\n", stats.LLMReportCount)
	return nil
}

func regularFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("inspect file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("expected regular file: %q", path)
	}
	return info.Size(), nil
}

func optionalRegularFileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("inspect file %q: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return 0, fmt.Errorf("expected regular file: %q", path)
	}
	return info.Size(), nil
}

func runIncidents(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("incidents", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	databasePath := flags.String("db", defaultDB, "SQLite database path")
	limit := flags.Int("limit", 50, "maximum incidents to print")
	if err := flags.Parse(args); err != nil || len(flags.Args()) != 0 {
		return errors.New("usage: tracejutsu incidents [--db path] [--limit count]")
	}

	database, err := openExistingSQLite(*databasePath)
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
		return errors.New("usage: tracejutsu show [--db path] <incident_id>")
	}

	database, err := openExistingSQLite(*databasePath)
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
		return errors.New("usage: tracejutsu llm [--db path] [--endpoint url] [--model name] [--timeout duration] [--allow-remote-endpoint] [--preserve-raw-response] <incident_id>")
	}

	database, err := openExistingSQLite(*databasePath)
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
		APIKey:              os.Getenv("TRACEJUTSU_LLM_API_KEY"),
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
	fmt.Fprintln(out, `tracejutsu: local-first runtime security analyst

Usage:
  tracejutsu demo [--db path] [fixture.json]       Run the fake-event incident pipeline
  tracejutsu run [--db path] [--flush-after time] [--stats-interval time] [--event-buffer count] [--persist-buffer count] [--persist-batch-size count] [--ring-buffer-size bytes] [--collectors list] [--file-write-min-bytes bytes] [--quiet-events]
                                                       Stream live runtime events and detect incidents (Linux amd64/arm64, root)
  tracejutsu events [--db path] [--limit count]    List stored normalized events
  tracejutsu event-summary [--db path] [--type event_type] [--limit count]
                                                       Summarize stored event volume by process and file path
  tracejutsu db-stats [--db path]                  Show SQLite table counts and file sizes
  tracejutsu incidents [--db path] [--limit count] List stored incidents
  tracejutsu show [--db path] <incident_id>        Show a stored incident
  tracejutsu llm [--db path] <incident_id>         Analyze a stored incident with a local LLM
  tracejutsu rules                List planned deterministic rules
  tracejutsu config               Print local-first default config
  tracejutsu version              Print build version metadata`)
}
