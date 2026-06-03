//go:build ebpf_smoke && linux && amd64

package ebpf

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"runtime-guard/internal/events"
)

func TestConnectCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	t.Run("IPv4", func(t *testing.T) {
		testConnectCollectorSmoke(t, "tcp4", "127.0.0.1:0", "127.0.0.1")
	})
	t.Run("IPv6", func(t *testing.T) {
		testConnectCollectorSmoke(t, "tcp6", "[::1]:0", "::1")
	})
}

func testConnectCollectorSmoke(t *testing.T, network, listenAddress, expectedAddress string) {
	t.Helper()
	listener, err := net.Listen(network, listenAddress)
	if err != nil {
		if network == "tcp6" {
			t.Skipf("IPv6 loopback is not available: %v", err)
		}
		t.Fatal(err)
	}
	defer listener.Close()
	endpoint := listener.Addr().(*net.TCPAddr)

	collector, err := NewConnectCollector()
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sink := make(chan events.Event)
	errors := make(chan error, 1)
	go func() {
		errors <- collector.Run(ctx, sink)
	}()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case event := <-sink:
			if event.RemoteAddr == expectedAddress &&
				event.RemotePort == endpoint.Port &&
				connectSmokeOutcomeAccepted(event) {
				cancel()
				return
			}
		case err := <-errors:
			if err != nil {
				t.Fatal(err)
			}
			t.Fatal("collector stopped before observing the test connection")
		case <-ticker.C:
			connection, err := net.DialTimeout(network, listener.Addr().String(), time.Second)
			if err == nil {
				connection.Close()
			}
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s connect event", network)
		}
	}
}

func connectSmokeOutcomeAccepted(event events.Event) bool {
	switch event.Metadata["outcome"] {
	case "success", "in_progress":
		return true
	default:
		return false
	}
}
