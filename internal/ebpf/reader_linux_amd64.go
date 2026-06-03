//go:build linux && amd64

package ebpf

import (
	"context"
	"io"
	"sync"
)

func closeOnContextCancel(ctx context.Context, closer io.Closer) func() {
	done := make(chan struct{})
	var stop sync.Once
	go func() {
		select {
		case <-ctx.Done():
			_ = closer.Close()
		case <-done:
		}
	}()
	return func() {
		stop.Do(func() {
			close(done)
		})
	}
}
