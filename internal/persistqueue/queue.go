package persistqueue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"runtime-guard/internal/events"
)

const (
	DefaultCapacity    = 1024
	DefaultSaveTimeout = 10 * time.Second
)

type EventSaver interface {
	SaveEvent(context.Context, events.Event) error
}

type Config struct {
	Capacity    int
	SaveTimeout time.Duration
}

type Stats struct {
	Received  uint64
	Enqueued  uint64
	Persisted uint64
	Dropped   uint64
}

type Queue struct {
	saver       EventSaver
	saveTimeout time.Duration
	events      chan events.Event
	done        chan struct{}
	errCh       chan error

	mu     sync.Mutex
	closed bool
	err    error

	received  uint64
	enqueued  uint64
	persisted uint64
	dropped   uint64
}

func New(saver EventSaver, capacity int) (*Queue, error) {
	return NewWithConfig(saver, Config{Capacity: capacity})
}

func NewWithConfig(saver EventSaver, config Config) (*Queue, error) {
	if saver == nil {
		return nil, errors.New("event saver is required")
	}
	if config.Capacity <= 0 {
		config.Capacity = DefaultCapacity
	}
	if config.SaveTimeout < 0 {
		return nil, errors.New("save timeout must be zero or positive")
	}
	if config.SaveTimeout == 0 {
		config.SaveTimeout = DefaultSaveTimeout
	}

	queue := &Queue{
		saver:       saver,
		saveTimeout: config.SaveTimeout,
		events:      make(chan events.Event, config.Capacity),
		done:        make(chan struct{}),
		errCh:       make(chan error, 1),
	}
	go queue.run()
	return queue, nil
}

func (queue *Queue) Enqueue(event events.Event) bool {
	queue.mu.Lock()
	defer queue.mu.Unlock()

	if queue.closed {
		atomic.AddUint64(&queue.received, 1)
		atomic.AddUint64(&queue.dropped, 1)
		return false
	}

	atomic.AddUint64(&queue.received, 1)
	select {
	case queue.events <- event:
		atomic.AddUint64(&queue.enqueued, 1)
		return true
	default:
		atomic.AddUint64(&queue.dropped, 1)
		return false
	}
}

func (queue *Queue) Close() error {
	queue.mu.Lock()
	if !queue.closed {
		queue.closed = true
		close(queue.events)
	}
	queue.mu.Unlock()

	<-queue.done
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.err
}

func (queue *Queue) Errors() <-chan error {
	return queue.errCh
}

func (queue *Queue) Stats() Stats {
	return Stats{
		Received:  atomic.LoadUint64(&queue.received),
		Enqueued:  atomic.LoadUint64(&queue.enqueued),
		Persisted: atomic.LoadUint64(&queue.persisted),
		Dropped:   atomic.LoadUint64(&queue.dropped),
	}
}

func (queue *Queue) run() {
	defer close(queue.done)

	for event := range queue.events {
		if err := queue.saveEvent(event); err != nil {
			queue.recordError(fmt.Errorf("save event %q: %w", event.EventID, err))
			return
		}
		atomic.AddUint64(&queue.persisted, 1)
	}
}

func (queue *Queue) recordError(err error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.err != nil {
		return
	}
	queue.err = err
	if !queue.closed {
		queue.closed = true
		close(queue.events)
	}
	select {
	case queue.errCh <- queue.err:
	default:
	}
}

func (queue *Queue) saveEvent(event events.Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), queue.saveTimeout)
	defer cancel()
	return queue.saver.SaveEvent(ctx, event)
}
