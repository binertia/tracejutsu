//go:build linux && amd64

package ebpf

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeConnectRecord(t *testing.T) {
	procRoot := t.TempDir()
	writeProcFile(t, procRoot, "4131/status", "Name:\tpayload\nPPid:\t4112\n")
	writeProcFile(t, procRoot, "4112/comm", "sh\n")
	if err := os.MkdirAll(filepath.Join(procRoot, "4131"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp/payload", filepath.Join(procRoot, "4131/exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(procRoot, "4131/cwd")); err != nil {
		t.Fatal(err)
	}

	raw := connectRecord{KernelTimestampNS: 123456, PID: 4131, UID: 33}
	copy(raw.Comm[:], "payload")
	binary.LittleEndian.PutUint16(raw.Sockaddr[0:2], addressFamilyIPv4)
	binary.BigEndian.PutUint16(raw.Sockaddr[2:4], 4444)
	copy(raw.Sockaddr[4:8], []byte{203, 0, 113, 10})

	collector := &ConnectCollector{host: "devbox-01", procRoot: procRoot}
	event, ok := collector.normalize(raw)
	if !ok {
		t.Fatal("expected IPv4 event to be normalized")
	}

	if event.ProcessName != "payload" || event.ParentProcessName != "sh" {
		t.Fatalf("process names = %q <- %q, want payload <- sh", event.ProcessName, event.ParentProcessName)
	}
	if event.ExecutablePath != "/tmp/payload" {
		t.Fatalf("executable path = %q, want /tmp/payload", event.ExecutablePath)
	}
	if event.RemoteAddr != "203.0.113.10" || event.RemotePort != 4444 {
		t.Fatalf("remote endpoint = %s:%d, want 203.0.113.10:4444", event.RemoteAddr, event.RemotePort)
	}
	if got := event.Metadata["address_family"]; got != "AF_INET" {
		t.Fatalf("address family = %#v, want AF_INET", got)
	}
}

func TestNormalizeConnectRecordIPv6(t *testing.T) {
	raw := connectRecord{KernelTimestampNS: 123456, PID: 4131, UID: 33}
	copy(raw.Comm[:], "payload")
	binary.LittleEndian.PutUint16(raw.Sockaddr[0:2], addressFamilyIPv6)
	binary.BigEndian.PutUint16(raw.Sockaddr[2:4], 4444)
	binary.LittleEndian.PutUint32(raw.Sockaddr[24:28], 7)
	copy(raw.Sockaddr[8:24], net.ParseIP("2001:db8::5").To16())

	collector := &ConnectCollector{host: "devbox-01", procRoot: t.TempDir()}
	event, ok := collector.normalize(raw)
	if !ok {
		t.Fatal("expected IPv6 event to be normalized")
	}

	if event.RemoteAddr != "2001:db8::5" || event.RemotePort != 4444 {
		t.Fatalf("remote endpoint = %s:%d, want [2001:db8::5]:4444", event.RemoteAddr, event.RemotePort)
	}
	if got := event.Metadata["address_family"]; got != "AF_INET6" {
		t.Fatalf("address family = %#v, want AF_INET6", got)
	}
	if got := event.Metadata["scope_id"]; got != uint32(7) {
		t.Fatalf("scope ID = %#v, want uint32(7)", got)
	}
}

func TestNormalizeConnectRecordSkipsUnsupportedFamily(t *testing.T) {
	raw := connectRecord{}
	binary.LittleEndian.PutUint16(raw.Sockaddr[0:2], 1)

	collector := &ConnectCollector{}
	if _, ok := collector.normalize(raw); ok {
		t.Fatal("expected unsupported socket address to be skipped")
	}
}
