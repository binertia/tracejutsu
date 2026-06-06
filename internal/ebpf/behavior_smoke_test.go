//go:build ebpf_smoke && linux && (amd64 || arm64)

package ebpf

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"tracejutsu/internal/events"
)

func TestSensitiveReadCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	collector, err := NewSensitiveReadCollector()
	if err != nil {
		t.Fatal(err)
	}

	runSmokeCollector(t, collector, func() {
		file, err := os.Open("/etc/passwd")
		if err == nil {
			file.Close()
		}
	}, func(event events.Event) bool {
		return event.EventType == events.TypeSensitiveRead &&
			event.FilePath == "/etc/passwd" &&
			event.Metadata["outcome"] == "success"
	}, "sensitive read")
}

func TestFileLifecycleCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	dir := t.TempDir()
	source := filepath.Join(dir, "source")
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(source, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}

	collector, err := NewFileLifecycleCollector()
	if err != nil {
		t.Fatal(err)
	}

	runSmokeCollector(t, collector, func() {
		if _, err := os.Stat(source); err == nil {
			_ = os.Rename(source, target)
			return
		}
		_ = os.Rename(target, source)
	}, func(event events.Event) bool {
		return event.EventType == events.TypeFileLifecycle &&
			event.Metadata["action"] == "rename" &&
			(event.FilePath == source || event.FilePath == target) &&
			event.Metadata["outcome"] == "success"
	}, "file lifecycle rename")
}

func TestPrivilegeChangeCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	collector, err := NewPrivilegeChangeCollector()
	if err != nil {
		t.Fatal(err)
	}

	runSmokeCollector(t, collector, func() {
		_ = unix.Prctl(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	}, func(event events.Event) bool {
		return event.EventType == events.TypePrivilegeChange &&
			event.Metadata["syscall"] == "prctl"
	}, "privilege prctl")
}

func TestNamespaceChangeCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	collector, err := NewNamespaceChangeCollector()
	if err != nil {
		t.Fatal(err)
	}

	runSmokeCollector(t, collector, func() {
		_, _, _ = unix.RawSyscall(unix.SYS_UNSHARE, 0, 0, 0)
	}, func(event events.Event) bool {
		return event.EventType == events.TypeNamespaceChange &&
			event.Metadata["syscall"] == "unshare"
	}, "namespace unshare")
}

func TestProcessAccessCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	collector, err := NewProcessAccessCollector()
	if err != nil {
		t.Fatal(err)
	}

	runSmokeCollector(t, collector, func() {
		_, _, _ = unix.RawSyscall6(unix.SYS_PROCESS_VM_READV, uintptr(os.Getpid()), 0, 0, 0, 0, 0)
	}, func(event events.Event) bool {
		return event.EventType == events.TypeProcessAccess &&
			event.Metadata["syscall"] == "process_vm_readv" &&
			event.Metadata["target_pid"] == uint64(os.Getpid())
	}, "process access")
}

func TestNetworkServerCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	collector, err := NewNetworkServerCollector()
	if err != nil {
		t.Fatal(err)
	}

	runSmokeCollector(t, collector, func() {
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err == nil {
			listener.Close()
		}
	}, func(event events.Event) bool {
		return event.EventType == events.TypeNetworkServer &&
			event.Metadata["syscall"] == "bind" &&
			event.RemoteAddr == "127.0.0.1" &&
			event.RemotePort != 0
	}, "network server bind")
}

func TestKernelTamperCollectorSmoke(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges are required for the eBPF smoke test")
	}

	collector, err := NewKernelTamperCollector()
	if err != nil {
		t.Fatal(err)
	}

	runSmokeCollector(t, collector, func() {
		_, _, _ = unix.RawSyscall(unix.SYS_BPF, 0, 0, 0)
	}, func(event events.Event) bool {
		return event.EventType == events.TypeKernelTamper &&
			event.Metadata["syscall"] == "bpf"
	}, "kernel tamper bpf")
}

func runSmokeCollector(t *testing.T, collector Collector, trigger func(), accept func(events.Event) bool, label string) {
	t.Helper()

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
			if accept(event) {
				cancel()
				waitForCollectorShutdown(t, errors)
				return
			}
		case err := <-errors:
			if err != nil {
				t.Fatal(err)
			}
			t.Fatalf("collector stopped before observing %s", label)
		case <-ticker.C:
			trigger()
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s event", label)
		}
	}
}
