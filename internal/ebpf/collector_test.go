package ebpf

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"runtime-guard/internal/events"
)

func TestCompositeCollectorForwardsChildEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	composite := NewCompositeCollector(
		collectorFunc(func(ctx context.Context, sink chan<- events.Event) error {
			select {
			case sink <- events.Event{EventID: "evt-001"}:
				return nil
			case <-ctx.Done():
				return nil
			}
		}),
	)
	sink := make(chan events.Event, 1)
	if err := composite.Run(ctx, sink); err != nil {
		t.Fatal(err)
	}
	if event := <-sink; event.EventID != "evt-001" {
		t.Fatalf("event ID = %q, want evt-001", event.EventID)
	}
}

func TestCompositeCollectorCancelsSiblingOnError(t *testing.T) {
	want := errors.New("collector failed")
	siblingCanceled := make(chan struct{})
	composite := NewCompositeCollector(
		collectorFunc(func(context.Context, chan<- events.Event) error {
			return want
		}),
		collectorFunc(func(ctx context.Context, _ chan<- events.Event) error {
			<-ctx.Done()
			close(siblingCanceled)
			return nil
		}),
	)

	if err := composite.Run(context.Background(), make(chan events.Event)); !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	select {
	case <-siblingCanceled:
	case <-time.After(time.Second):
		t.Fatal("sibling collector was not canceled")
	}
}

func TestCompositeCollectorCombinesChildStats(t *testing.T) {
	composite := NewCompositeCollector(
		statsCollector{name: "execve", stats: Stats{RingBufferDropped: 3, CorrelationDropped: 2}},
		statsCollector{name: "file_write", stats: Stats{RingBufferDropped: 5, CorrelationDropped: 4}},
	)

	stats := composite.Stats()
	if got := stats.RingBufferDropped; got != 8 {
		t.Fatalf("ring buffer dropped = %d, want 8", got)
	}
	if got := stats.CorrelationDropped; got != 6 {
		t.Fatalf("correlation dropped = %d, want 6", got)
	}

	details := composite.StatsByCollector()
	if len(details) != 2 {
		t.Fatalf("details count = %d, want 2", len(details))
	}
	if details[0].Name != "execve" || details[0].Stats.RingBufferDropped != 3 {
		t.Fatalf("first detail = %#v, want execve with ring drops", details[0])
	}
	if details[1].Name != "file_write" || details[1].Stats.CorrelationDropped != 4 {
		t.Fatalf("second detail = %#v, want file_write with correlation drops", details[1])
	}
}

func TestCheckedRuntimeConfigDefaultsRingBufferSize(t *testing.T) {
	config, err := checkedRuntimeConfig(RuntimeConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if config.RingBufferSize != DefaultRingBufferSize {
		t.Fatalf("ring buffer size = %d, want %d", config.RingBufferSize, DefaultRingBufferSize)
	}
}

func TestCheckedRuntimeConfigRejectsInvalidRingBufferSize(t *testing.T) {
	for _, size := range []int{-1, 1, 12 * 1024 * 1024} {
		if _, err := checkedRuntimeConfig(RuntimeConfig{RingBufferSize: size}); err == nil {
			t.Fatalf("ring buffer size %d should fail", size)
		}
	}
}

func TestCheckedRuntimeConfigRejectsInvalidFileWriteMinimum(t *testing.T) {
	for _, minimum := range []int64{-1, maxBPFImmediate + 1} {
		if _, err := checkedRuntimeConfig(RuntimeConfig{FileWriteMinBytes: minimum}); err == nil {
			t.Fatalf("file write minimum %d should fail", minimum)
		}
	}
}

func TestCheckedRuntimeConfigRejectsInvalidFileWriteIgnoredPID(t *testing.T) {
	for _, pid := range []int{-1, int(maxBPFImmediate) + 1} {
		if _, err := checkedRuntimeConfig(RuntimeConfig{FileWriteIgnorePID: pid}); err == nil {
			t.Fatalf("file write ignored PID %d should fail", pid)
		}
	}
}

func TestParseCollectorNames(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "default",
			input: "",
			want:  DefaultCollectorNames(),
		},
		{
			name:  "all",
			input: "all",
			want:  DefaultCollectorNames(),
		},
		{
			name:  "subset",
			input: " execve,connect ",
			want:  []string{CollectorExecve, CollectorConnect},
		},
		{
			name:  "normalized case",
			input: "FILE_WRITE,CHMOD",
			want:  []string{CollectorFileWrite, CollectorChmod},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := ParseCollectorNames(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("collectors = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParseCollectorNamesRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"execve,,connect", "unknown", "all,execve", "connect,connect"} {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseCollectorNames(input); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

type collectorFunc func(ctx context.Context, sink chan<- events.Event) error

func (function collectorFunc) Run(ctx context.Context, sink chan<- events.Event) error {
	return function(ctx, sink)
}

type statsCollector struct {
	name  string
	stats Stats
}

func (statsCollector) Run(context.Context, chan<- events.Event) error {
	return nil
}

func (collector statsCollector) Stats() Stats {
	return collector.stats
}

func (collector statsCollector) Name() string {
	return collector.name
}
