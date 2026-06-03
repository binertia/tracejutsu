//go:build linux && amd64

package ebpf

import (
	"context"
	"sync"
	"testing"
	"time"
)

type testCloser struct {
	closed chan struct{}
	once   sync.Once
}

func (closer *testCloser) Close() error {
	closer.once.Do(func() {
		close(closer.closed)
	})
	return nil
}

func TestCloseOnContextCancelClosesCloser(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	closer := &testCloser{closed: make(chan struct{})}
	stop := closeOnContextCancel(ctx, closer)
	defer stop()

	cancel()
	select {
	case <-closer.closed:
	case <-time.After(time.Second):
		t.Fatal("closer was not closed after context cancellation")
	}
}

func TestCloseOnContextCancelStopIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closer := &testCloser{closed: make(chan struct{})}
	stop := closeOnContextCancel(ctx, closer)

	stop()
	stop()
}
