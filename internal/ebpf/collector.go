// Package ebpf defines the collector boundary. Kernel probe loading is added
// only after the fake-event pipeline is stable.
package ebpf

import (
	"context"
	"errors"
	"fmt"
	"os"

	"runtime-guard/internal/events"
)

const DefaultRingBufferSize = 8 * 1024 * 1024

type Collector interface {
	Run(ctx context.Context, sink chan<- events.Event) error
}

type NamedCollector interface {
	Name() string
}

type RuntimeConfig struct {
	RingBufferSize int
}

type Stats struct {
	RingBufferDropped  uint64
	CorrelationDropped uint64
}

type StatsProvider interface {
	Stats() Stats
}

type CollectorStats struct {
	Name  string
	Stats Stats
}

type StatsDetailProvider interface {
	StatsByCollector() []CollectorStats
}

type CompositeCollector struct {
	collectors []Collector
}

func NewCompositeCollector(collectors ...Collector) *CompositeCollector {
	return &CompositeCollector{collectors: collectors}
}

func (collector *CompositeCollector) Stats() Stats {
	var combined Stats
	for _, detail := range collector.StatsByCollector() {
		combined.RingBufferDropped += detail.Stats.RingBufferDropped
		combined.CorrelationDropped += detail.Stats.CorrelationDropped
	}
	return combined
}

func (collector *CompositeCollector) StatsByCollector() []CollectorStats {
	details := make([]CollectorStats, 0, len(collector.collectors))
	for index, child := range collector.collectors {
		provider, ok := child.(StatsProvider)
		if !ok {
			continue
		}
		name := fmt.Sprintf("collector_%d", index)
		if named, ok := child.(NamedCollector); ok {
			name = named.Name()
		}
		details = append(details, CollectorStats{Name: name, Stats: provider.Stats()})
	}
	return details
}

func (collector *CompositeCollector) Run(ctx context.Context, sink chan<- events.Event) error {
	if sink == nil {
		return errors.New("event sink is required")
	}
	if len(collector.collectors) == 0 {
		return errors.New("at least one collector is required")
	}

	runContext, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan error, len(collector.collectors))
	for _, child := range collector.collectors {
		go func() {
			results <- child.Run(runContext, sink)
		}()
	}

	var firstError error
	for index := range collector.collectors {
		if err := <-results; err != nil && firstError == nil {
			firstError = err
		}
		if index == 0 {
			cancel()
		}
	}
	return firstError
}

func checkedRuntimeConfig(config RuntimeConfig) (RuntimeConfig, error) {
	if config.RingBufferSize == 0 {
		config.RingBufferSize = DefaultRingBufferSize
	}
	if config.RingBufferSize < 0 {
		return RuntimeConfig{}, errors.New("collector ring buffer size must be positive")
	}
	pageSize := os.Getpagesize()
	if config.RingBufferSize < pageSize {
		return RuntimeConfig{}, fmt.Errorf("collector ring buffer size must be at least one page (%d bytes)", pageSize)
	}
	if uint64(config.RingBufferSize) > uint64(^uint32(0)) {
		return RuntimeConfig{}, errors.New("collector ring buffer size must fit in uint32")
	}
	if config.RingBufferSize&(config.RingBufferSize-1) != 0 {
		return RuntimeConfig{}, errors.New("collector ring buffer size must be a power of two")
	}
	return config, nil
}
