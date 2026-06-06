//go:build linux && (amd64 || arm64)

package ebpf

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeSensitiveReadRecordFiltersReadableSensitivePath(t *testing.T) {
	procRoot := t.TempDir()
	writeProcFile(t, procRoot, "5001/status", "Name:\tbash\nPPid:\t5000\n")
	writeProcFile(t, procRoot, "5000/comm", "sshd\n")
	if err := os.MkdirAll(filepath.Join(procRoot, "5001"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/bin/bash", filepath.Join(procRoot, "5001/exe")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/root", filepath.Join(procRoot, "5001/cwd")); err != nil {
		t.Fatal(err)
	}

	raw := sensitiveReadRecord{PID: 5001, UID: 0, FD: atFDCWD, Syscall: openatSyscallNumber}
	copy(raw.Comm[:], "bash")
	copy(raw.FilePath[:], ".ssh/id_rsa")

	collector := &SensitiveReadCollector{host: "devbox-01", procRoot: procRoot}
	event, ok := collector.normalize(raw)
	if !ok {
		t.Fatal("expected sensitive read event")
	}
	if event.EventType != "sensitive_read" || event.FilePath != "/root/.ssh/id_rsa" {
		t.Fatalf("event = %#v, want sensitive read of /root/.ssh/id_rsa", event)
	}
	if got := event.Metadata["access_mode"]; got != "read_only" {
		t.Fatalf("access mode = %#v, want read_only", got)
	}

	raw.Flags = openWriteOnly
	if _, ok := collector.normalize(raw); ok {
		t.Fatal("expected write-only open to be skipped")
	}
}

func TestNormalizeFileLifecycleRecordResolvesTwoPathRename(t *testing.T) {
	procRoot := t.TempDir()
	if err := os.MkdirAll(filepath.Join(procRoot, "5002/fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/tmp", filepath.Join(procRoot, "5002/fd/9")); err != nil {
		t.Fatal(err)
	}
	raw := fileLifecycleRecord{
		PID:      5002,
		UID:      1000,
		SourceFD: atFDCWD,
		TargetFD: 9,
		Syscall:  renameat2SyscallNumber,
	}
	copy(raw.Comm[:], "mv")
	copy(raw.SourcePath[:], "/var/log/auth.log")
	copy(raw.TargetPath[:], "auth.log.1")

	collector := &FileLifecycleCollector{host: "devbox-01", procRoot: procRoot}
	event, ok := collector.normalize(raw)
	if !ok {
		t.Fatal("expected file lifecycle event")
	}
	if event.FilePath != "/tmp/auth.log.1" {
		t.Fatalf("file path = %q, want /tmp/auth.log.1", event.FilePath)
	}
	if got := event.Metadata["source_path"]; got != "/var/log/auth.log" {
		t.Fatalf("source path = %#v, want /var/log/auth.log", got)
	}
	if got := event.Metadata["action"]; got != "rename" {
		t.Fatalf("action = %#v, want rename", got)
	}
}

func TestNormalizeBehaviorSyscallRecordAddsTargetPID(t *testing.T) {
	collector := &BehaviorSyscallCollector{
		host:      "devbox-01",
		procRoot:  t.TempDir(),
		name:      CollectorProcessAccess,
		eventType: "process_access",
		syscalls:  map[uint32]string{processVMWritevSyscallNumber: "process_vm_writev"},
	}
	raw := behaviorSyscallRecord{PID: 5003, UID: 1000, Syscall: processVMWritevSyscallNumber, Args: [3]uint64{1234, 0, 0}}
	copy(raw.Comm[:], "python")

	event := collector.normalize(raw)
	if event.EventType != "process_access" {
		t.Fatalf("event type = %q, want process_access", event.EventType)
	}
	if got := event.Metadata["target_pid"]; got != uint64(1234) {
		t.Fatalf("target pid = %#v, want uint64(1234)", got)
	}
}

func TestNormalizeNetworkServerBindRecord(t *testing.T) {
	raw := networkServerRecord{PID: 5004, UID: 1000, Syscall: bindSyscallNumber, FD: 8}
	copy(raw.Comm[:], "nc")
	binary.LittleEndian.PutUint16(raw.Sockaddr[0:2], addressFamilyIPv6)
	binary.BigEndian.PutUint16(raw.Sockaddr[2:4], 4444)
	copy(raw.Sockaddr[8:24], net.ParseIP("2001:db8::5").To16())

	collector := &NetworkServerCollector{host: "devbox-01", procRoot: t.TempDir()}
	event, ok := collector.normalize(raw)
	if !ok {
		t.Fatal("expected network server event")
	}
	if event.RemoteAddr != "2001:db8::5" || event.RemotePort != 4444 {
		t.Fatalf("endpoint = %s:%d, want [2001:db8::5]:4444", event.RemoteAddr, event.RemotePort)
	}
	if got := event.Metadata["syscall"]; got != "bind" {
		t.Fatalf("syscall = %#v, want bind", got)
	}
}
