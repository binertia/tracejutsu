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
	DefaultCapacity    = 8192
	DefaultBatchSize   = 256
	DefaultSaveTimeout = 10 * time.Second
)

type EventSaver interface {
	SaveEvent(context.Context, events.Event) error
}

type EventBatchSaver interface {
	SaveEvents(context.Context, []events.Event) error
}

type Config struct {
	Capacity    int
	BatchSize   int
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
	batchSize   int
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
	if config.BatchSize <= 0 {
		config.BatchSize = DefaultBatchSize
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
		batchSize:   config.BatchSize,
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
		batch := queue.collectBatch(event)
		if err := queue.saveBatch(batch); err != nil {
			queue.recordError(len(batch), describeBatchError(batch, err))
			return
		}
		atomic.AddUint64(&queue.persisted, uint64(len(batch)))
	}
}

func (queue *Queue) collectBatch(first events.Event) []events.Event {
	if _, ok := queue.saver.(EventBatchSaver); !ok {
		return []events.Event{first}
	}
	batch := make([]events.Event, 0, queue.batchSize)
	batch = append(batch, first)
	for len(batch) < queue.batchSize {
		select {
		case event, ok := <-queue.events:
			if !ok {
				return batch
			}
			batch = append(batch, event)
		default:
			return batch
		}
	}
	return batch
}

func (queue *Queue) recordError(failedEvents int, err error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if queue.err != nil {
		return
	}
	queue.err = err
	atomic.AddUint64(&queue.dropped, uint64(failedEvents+len(queue.events)))
	if !queue.closed {
		queue.closed = true
		close(queue.events)
	}
	select {
	case queue.errCh <- queue.err:
	default:
	}
}

func (queue *Queue) saveBatch(batch []events.Event) error {
	ctx, cancel := context.WithTimeout(context.Background(), queue.saveTimeout)
	defer cancel()
	if batchSaver, ok := queue.saver.(EventBatchSaver); ok {
		return batchSaver.SaveEvents(ctx, batch)
	}
	return queue.saver.SaveEvent(ctx, batch[0])
}

func describeBatchError(batch []events.Event, err error) error {
	if len(batch) == 1 {
		return fmt.Errorf("save event %q: %w", batch[0].EventID, err)
	}
	return fmt.Errorf("save event batch starting with %q (%d events): %w", batch[0].EventID, len(batch), err)
}
