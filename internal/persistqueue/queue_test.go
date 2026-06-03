package persistqueue

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"runtime-guard/internal/events"
)

type blockingSaver struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	events  []string
}

func (s *blockingSaver) SaveEvent(_ context.Context, event events.Event) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-s.release
	s.mu.Lock()
	s.events = append(s.events, event.EventID)
	s.mu.Unlock()
	return nil
}

type errorSaver struct{}

func (errorSaver) SaveEvent(context.Context, events.Event) error {
	return errors.New("boom")
}

type contextBlockingSaver struct {
	started chan struct{}
}

func (s contextBlockingSaver) SaveEvent(ctx context.Context, _ events.Event) error {
	select {
	case s.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return ctx.Err()
}

func TestQueueDropsWhenCapacityIsExceeded(t *testing.T) {
	saver := &blockingSaver{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	queue, err := New(saver, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		close(saver.release)
		if closeErr := queue.Close(); closeErr != nil {
			t.Fatal(closeErr)
		}
	}()

	first := events.Event{EventID: "evt-1"}
	second := events.Event{EventID: "evt-2"}
	third := events.Event{EventID: "evt-3"}

	if !queue.Enqueue(first) {
		t.Fatal("first enqueue dropped unexpectedly")
	}
	select {
	case <-saver.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	if !queue.Enqueue(second) {
		t.Fatal("second enqueue dropped unexpectedly")
	}
	if queue.Enqueue(third) {
		t.Fatal("third enqueue should have been dropped")
	}

	<-time.After(10 * time.Millisecond)
	stats := queue.Stats()
	if stats.Received != 3 || stats.Enqueued != 2 || stats.Dropped != 1 {
		t.Fatalf("stats = %#v, want received=3 enqueued=2 dropped=1", stats)
	}
}

func TestQueueCloseFlushesPendingEvents(t *testing.T) {
	saver := &blockingSaver{
		started: make(chan struct{}, 1),
		release: make(chan struct{}),
	}
	queue, err := New(saver, 4)
	if err != nil {
		t.Fatal(err)
	}

	for _, eventID := range []string{"evt-1", "evt-2"} {
		if !queue.Enqueue(events.Event{EventID: eventID}) {
			t.Fatalf("enqueue %q dropped unexpectedly", eventID)
		}
	}
	select {
	case <-saver.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	close(saver.release)
	if err := queue.Close(); err != nil {
		t.Fatal(err)
	}

	saver.mu.Lock()
	defer saver.mu.Unlock()
	if len(saver.events) != 2 {
		t.Fatalf("persisted events = %d, want 2", len(saver.events))
	}
	stats := queue.Stats()
	if stats.Persisted != 2 || stats.Dropped != 0 {
		t.Fatalf("stats = %#v, want persisted=2 dropped=0", stats)
	}
}

func TestQueueReportsSaverError(t *testing.T) {
	queue, err := New(errorSaver{}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !queue.Enqueue(events.Event{EventID: "evt-1"}) {
		t.Fatal("enqueue dropped unexpectedly")
	}

	select {
	case got := <-queue.Errors():
		if got == nil {
			t.Fatal("error channel yielded nil")
		}
	case <-time.After(time.Second):
		t.Fatal("expected saver error")
	}

	if queue.Enqueue(events.Event{EventID: "evt-after-error"}) {
		t.Fatal("enqueue after saver error should have been dropped")
	}

	if err := queue.Close(); err == nil {
		t.Fatal("close should report saver error")
	}
}

func TestQueueSaveTimeoutUnblocksClose(t *testing.T) {
	saver := contextBlockingSaver{started: make(chan struct{}, 1)}
	queue, err := NewWithConfig(saver, Config{
		Capacity:    1,
		SaveTimeout: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !queue.Enqueue(events.Event{EventID: "evt-timeout"}) {
		t.Fatal("enqueue dropped unexpectedly")
	}

	select {
	case <-saver.started:
	case <-time.After(time.Second):
		t.Fatal("worker did not start")
	}

	started := time.Now()
	err = queue.Close()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close error = %v, want context deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("close took %s, want bounded timeout", elapsed)
	}
	stats := queue.Stats()
	if stats.Persisted != 0 {
		t.Fatalf("persisted = %d, want 0", stats.Persisted)
	}
}

func TestQueueRejectsNegativeSaveTimeout(t *testing.T) {
	if _, err := NewWithConfig(errorSaver{}, Config{SaveTimeout: -time.Second}); err == nil {
		t.Fatal("expected negative save timeout to fail")
	}
}
