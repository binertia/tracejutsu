//go:build linux && amd64

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"runtime-guard/internal/events"
)

const (
	connectSyscallNumber = 42
	ptRegsSIOffset       = 104
	addressFamilyIPv4    = 2
	addressFamilyIPv6    = 10
	sockaddrFamilySize   = 2
	sockaddrIPv4Size     = 16
	sockaddrIPv6Size     = 28
	sockaddrStorageSize  = 32
)

type ConnectCollector struct {
	host           string
	procRoot       string
	containerCache *containerMetadataCache
	metrics        collectorMetrics
	sequence       atomic.Uint64
}

type connectRecord struct {
	KernelTimestampNS uint64
	PID               uint32
	UID               uint32
	Comm              [commSize]byte
	Sockaddr          [sockaddrStorageSize]byte
}

func NewConnectCollector() (*ConnectCollector, error) {
	host, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}
	return &ConnectCollector{host: host, procRoot: "/proc", containerCache: newContainerMetadataCache()}, nil
}

func NewRuntimeCollector() (Collector, error) {
	execve, err := NewExecveCollector()
	if err != nil {
		return nil, err
	}
	connect, err := NewConnectCollector()
	if err != nil {
		return nil, err
	}
	fileWrite, err := NewFileWriteCollector()
	if err != nil {
		return nil, err
	}
	chmod, err := NewChmodCollector()
	if err != nil {
		return nil, err
	}
	return NewCompositeCollector(execve, connect, fileWrite, chmod), nil
}

// Run attaches an amd64 raw tracepoint collector and emits normalized IPv4 and
// IPv6 connect attempts until the context is canceled.
func (collector *ConnectCollector) Run(ctx context.Context, sink chan<- events.Event) error {
	if sink == nil {
		return errors.New("event sink is required")
	}
	_ = rlimit.RemoveMemlock()

	records, err := cebpf.NewMap(&cebpf.MapSpec{
		Type:       cebpf.RingBuf,
		Name:       "rg_connect_rb",
		MaxEntries: ringBufferSize,
	})
	if err != nil {
		return fmt.Errorf("create connect ring buffer: %w", err)
	}
	defer records.Close()

	drops, err := newDropCounterMap("rg_connect_drop")
	if err != nil {
		return fmt.Errorf("create connect drop counter: %w", err)
	}
	defer drops.Close()
	collector.metrics.attachDropCounter(drops)
	defer collector.metrics.detachDropCounter(drops)

	program, err := cebpf.NewProgram(connectProgramSpec(records.FD(), drops.FD()))
	if err != nil {
		return fmt.Errorf("load connect raw tracepoint program: %w", err)
	}
	defer program.Close()

	hook, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: program,
	})
	if err != nil {
		return fmt.Errorf("attach sys_enter raw tracepoint: %w", err)
	}
	defer hook.Close()

	reader, err := ringbuf.NewReader(records)
	if err != nil {
		return fmt.Errorf("open connect ring buffer reader: %w", err)
	}
	defer reader.Close()

	readerDone := make(chan struct{})
	defer close(readerDone)
	go func() {
		select {
		case <-ctx.Done():
			_ = reader.Close()
		case <-readerDone:
		}
	}()

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read connect ring buffer: %w", err)
		}

		raw, err := decodeConnectRecord(record.RawSample)
		if err != nil {
			return err
		}
		event, ok := collector.normalize(raw)
		if !ok {
			continue
		}

		select {
		case sink <- event:
		case <-ctx.Done():
			return nil
		}
	}
}

func (collector *ConnectCollector) Stats() Stats {
	return collector.metrics.stats()
}

func connectProgramSpec(ringBufferFD, dropCounterFD int) *cebpf.ProgramSpec {
	const sockaddrOffset = int16(32)
	recordSize := int16(binary.Size(connectRecord{}))
	recordStart := -recordSize
	tempPointer := recordStart - 8

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R7, asm.R6, 8, asm.DWord),
		asm.JNE.Imm(asm.R7, connectSyscallNumber, "exit"),
		asm.Mov.Imm(asm.R0, 0),
	}
	for offset := recordStart; offset < 0; offset += 8 {
		instructions = append(instructions, asm.StoreMem(asm.RFP, offset, asm.R0, asm.DWord))
	}

	instructions = append(instructions,
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, recordStart, asm.R0, asm.DWord),

		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, recordStart+8, asm.R0, asm.Word),

		asm.FnGetCurrentUidGid.Call(),
		asm.StoreMem(asm.RFP, recordStart+12, asm.R0, asm.Word),

		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(recordStart+16)),
		asm.Mov.Imm(asm.R2, commSize),
		asm.FnGetCurrentComm.Call(),

		asm.LoadMem(asm.R3, asm.R6, 0, asm.DWord),
		asm.Add.Imm(asm.R3, ptRegsSIOffset),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(tempPointer)),
		asm.Mov.Imm(asm.R2, 8),
		asm.FnProbeReadKernel.Call(),

		asm.LoadMem(asm.R3, asm.RFP, tempPointer, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(recordStart+sockaddrOffset)),
		asm.Mov.Imm(asm.R2, sockaddrFamilySize),
		asm.FnProbeReadUser.Call(),

		asm.LoadMem(asm.R7, asm.RFP, recordStart+sockaddrOffset, asm.Half),
		asm.JEq.Imm(asm.R7, addressFamilyIPv4, "read_ipv4"),
		asm.JEq.Imm(asm.R7, addressFamilyIPv6, "read_ipv6"),
		asm.Ja.Label("exit"),
	)

	instructions = append(instructions,
		asm.LoadMem(asm.R3, asm.RFP, tempPointer, asm.DWord).WithSymbol("read_ipv4"),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(recordStart+sockaddrOffset)),
		asm.Mov.Imm(asm.R2, sockaddrIPv4Size),
		asm.FnProbeReadUser.Call(),
		asm.Ja.Label("emit"),
	)
	instructions = append(instructions,
		asm.LoadMem(asm.R3, asm.RFP, tempPointer, asm.DWord).WithSymbol("read_ipv6"),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(recordStart+sockaddrOffset)),
		asm.Mov.Imm(asm.R2, sockaddrIPv6Size),
		asm.FnProbeReadUser.Call(),
		asm.Ja.Label("emit"),
	)
	instructions = append(instructions,
		asm.LoadMapPtr(asm.R1, ringBufferFD).WithSymbol("emit"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(recordStart)),
		asm.Mov.Imm(asm.R3, int32(recordSize)),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
	)
	instructions = append(instructions, countRingBufferDrop(dropCounterFD, tempPointer)...)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)

	return &cebpf.ProgramSpec{
		Name:         "rg_connect",
		Type:         cebpf.RawTracepoint,
		License:      "GPL",
		Instructions: instructions,
	}
}

func decodeConnectRecord(raw []byte) (connectRecord, error) {
	var decoded connectRecord
	if len(raw) != binary.Size(decoded) {
		return decoded, fmt.Errorf("decode connect record: size %d, want %d", len(raw), binary.Size(decoded))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &decoded); err != nil {
		return decoded, fmt.Errorf("decode connect record: %w", err)
	}
	return decoded, nil
}

func (collector *ConnectCollector) normalize(raw connectRecord) (events.Event, bool) {
	remoteAddr, remotePort, addressFamily, metadata, ok := decodeSockaddr(raw.Sockaddr)
	if !ok {
		return events.Event{}, false
	}

	timestamp := time.Now().UTC()
	pid := int(raw.PID)
	ppid := readProcPPID(collector.procRoot, pid)
	executablePath := readProcExe(collector.procRoot, pid)
	processName := cString(raw.Comm[:])
	if executablePath != "" {
		processName = filepath.Base(executablePath)
	}

	event := events.Event{
		EventID:           fmt.Sprintf("connect-%d-%d-%d", timestamp.UnixNano(), pid, collector.sequence.Add(1)),
		Timestamp:         timestamp,
		Host:              collector.host,
		PID:               pid,
		PPID:              ppid,
		UID:               int(raw.UID),
		ProcessName:       processName,
		ParentProcessName: readProcComm(collector.procRoot, ppid),
		EventType:         events.TypeConnect,
		ExecutablePath:    executablePath,
		CWD:               readProcCWD(collector.procRoot, pid),
		RemoteAddr:        remoteAddr,
		RemotePort:        remotePort,
		Metadata: map[string]any{
			"source":              "ebpf_raw_tracepoint_sys_enter",
			"kernel_timestamp_ns": raw.KernelTimestampNS,
			"address_family":      addressFamily,
		},
	}
	for key, value := range metadata {
		event.Metadata[key] = value
	}
	enrichContainerMetadata(&event, collector.procRoot, pid, collector.containerCache)
	return event, true
}

func decodeSockaddr(raw [sockaddrStorageSize]byte) (string, int, string, map[string]any, bool) {
	switch family := binary.LittleEndian.Uint16(raw[0:2]); family {
	case addressFamilyIPv4:
		return net.IP(raw[4:8]).String(),
			int(binary.BigEndian.Uint16(raw[2:4])),
			"AF_INET",
			nil,
			true
	case addressFamilyIPv6:
		metadata := make(map[string]any)
		if flowInfo := binary.LittleEndian.Uint32(raw[4:8]); flowInfo != 0 {
			metadata["flowinfo"] = flowInfo
		}
		if scopeID := binary.LittleEndian.Uint32(raw[24:28]); scopeID != 0 {
			metadata["scope_id"] = scopeID
		}
		return net.IP(raw[8:24]).String(),
			int(binary.BigEndian.Uint16(raw[2:4])),
			"AF_INET6",
			metadata,
			true
	default:
		return "", 0, "", nil, false
	}
}
