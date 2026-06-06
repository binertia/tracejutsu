//go:build linux && (amd64 || arm64)

package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"tracejutsu/internal/events"
)

const (
	openAccessModeMask = 0x3
	openWriteOnly      = 0x1
)

type SensitiveReadCollector struct {
	host           string
	procRoot       string
	containerCache *containerMetadataCache
	ringBufferSize int
	metrics        collectorMetrics
	sequence       atomic.Uint64
}

type sensitiveReadRecord struct {
	KernelTimestampNS           uint64
	CompletionKernelTimestampNS uint64
	ReturnValue                 int64
	PID                         uint32
	UID                         uint32
	Comm                        [commSize]byte
	FilePath                    [filenameSize]byte
	FD                          int32
	Syscall                     uint32
	Flags                       uint64
}

func NewSensitiveReadCollector() (*SensitiveReadCollector, error) {
	return NewSensitiveReadCollectorWithConfig(RuntimeConfig{})
}

func NewSensitiveReadCollectorWithConfig(config RuntimeConfig) (*SensitiveReadCollector, error) {
	config, err := checkedRuntimeConfig(config)
	if err != nil {
		return nil, err
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}
	return &SensitiveReadCollector{
		host:           host,
		procRoot:       "/proc",
		containerCache: newContainerMetadataCache(),
		ringBufferSize: config.RingBufferSize,
	}, nil
}

func (collector *SensitiveReadCollector) Run(ctx context.Context, sink chan<- events.Event) error {
	if sink == nil {
		return errors.New("event sink is required")
	}
	_ = rlimit.RemoveMemlock()

	records, err := cebpf.NewMap(&cebpf.MapSpec{
		Type:       cebpf.RingBuf,
		Name:       "rg_sread_rb",
		MaxEntries: uint32(collector.ringBufferSize),
	})
	if err != nil {
		return fmt.Errorf("create sensitive read ring buffer: %w", err)
	}
	defer records.Close()

	pending, err := newPendingSyscallMap("rg_sread_pend", binary.Size(sensitiveReadRecord{}))
	if err != nil {
		return fmt.Errorf("create pending sensitive read map: %w", err)
	}
	defer pending.Close()

	drops, err := newDropCounterMap("rg_sread_drop")
	if err != nil {
		return fmt.Errorf("create sensitive read drop counter: %w", err)
	}
	defer drops.Close()
	collector.metrics.attachDropCounter(drops)
	defer collector.metrics.detachDropCounter(drops)

	correlationDrops, err := newDropCounterMap("rg_sread_cd")
	if err != nil {
		return fmt.Errorf("create sensitive read correlation drop counter: %w", err)
	}
	defer correlationDrops.Close()
	collector.metrics.attachCorrelationDropCounter(correlationDrops)
	defer collector.metrics.detachCorrelationDropCounter(correlationDrops)

	enterProgram, err := cebpf.NewProgram(sensitiveReadEnterProgramSpec(pending.FD(), correlationDrops.FD()))
	if err != nil {
		return fmt.Errorf("load sensitive read sys_enter raw tracepoint program: %w", err)
	}
	defer enterProgram.Close()

	enterHook, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: enterProgram})
	if err != nil {
		return fmt.Errorf("attach sys_enter raw tracepoint: %w", err)
	}
	defer enterHook.Close()

	exitProgram, err := cebpf.NewProgram(sensitiveReadExitProgramSpec(records.FD(), drops.FD(), pending.FD()))
	if err != nil {
		return fmt.Errorf("load sensitive read sys_exit raw tracepoint program: %w", err)
	}
	defer exitProgram.Close()

	exitHook, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_exit", Program: exitProgram})
	if err != nil {
		return fmt.Errorf("attach sys_exit raw tracepoint: %w", err)
	}
	defer exitHook.Close()

	reader, err := ringbuf.NewReader(records)
	if err != nil {
		return fmt.Errorf("open sensitive read ring buffer reader: %w", err)
	}
	defer reader.Close()

	stopReaderClose := closeOnContextCancel(ctx, reader)
	defer stopReaderClose()

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) && ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read sensitive read ring buffer: %w", err)
		}
		raw, err := decodeSensitiveReadRecord(record.RawSample)
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

func (collector *SensitiveReadCollector) Stats() Stats {
	return collector.metrics.stats()
}

func (*SensitiveReadCollector) Name() string {
	return CollectorSensitiveRead
}

func sensitiveReadEnterProgramSpec(pendingFD, correlationDropCounterFD int) *cebpf.ProgramSpec {
	const (
		pidOffset     = int16(24)
		uidOffset     = int16(28)
		commOffset    = int16(32)
		pathOffset    = int16(48)
		fdOffset      = int16(304)
		syscallOffset = int16(308)
		flagsOffset   = int16(312)
	)
	recordSize := int16(binary.Size(sensitiveReadRecord{}))
	recordStart := -recordSize
	keyOffset := recordStart - 8
	tempPointer := keyOffset - 8
	tempValue := tempPointer - 8

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord),
	}
	if hasOpenSyscall {
		instructions = append(instructions, asm.JEq.Imm(asm.R8, openSyscallNumber, "capture_open"))
	}
	instructions = append(instructions,
		asm.JEq.Imm(asm.R8, openatSyscallNumber, "capture_openat"),
		asm.JEq.Imm(asm.R8, openat2SyscallNumber, "capture_openat2"),
		asm.Ja.Label("exit"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("init"),
	)
	for offset := recordStart; offset < 0; offset += 8 {
		instructions = append(instructions, asm.StoreMem(asm.RFP, offset, asm.R0, asm.DWord))
	}
	instructions = append(instructions,
		asm.StoreMem(asm.RFP, recordStart+syscallOffset, asm.R8, asm.Word),
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, recordStart, asm.R0, asm.DWord),
		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, keyOffset, asm.R0, asm.DWord),
		asm.RSh.Imm(asm.R0, 32),
		asm.StoreMem(asm.RFP, recordStart+pidOffset, asm.R0, asm.Word),
		asm.FnGetCurrentUidGid.Call(),
		asm.StoreMem(asm.RFP, recordStart+uidOffset, asm.R0, asm.Word),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(recordStart+commOffset)),
		asm.Mov.Imm(asm.R2, commSize),
		asm.FnGetCurrentComm.Call(),
	)
	if hasOpenSyscall {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_open"))
		instructions = append(instructions,
			readPathArgument(asm.R6, syscallArg0Offset, asm.RFP, tempValue, recordStart+pathOffset)...,
		)
		instructions = append(instructions,
			readRegisterArgument(asm.R6, syscallArg1Offset, asm.RFP, tempValue, recordStart+flagsOffset, asm.DWord)...,
		)
		instructions = append(instructions,
			asm.Mov.Imm(asm.R7, atFDCWD),
			asm.StoreMem(asm.RFP, recordStart+fdOffset, asm.R7, asm.Word),
			asm.Ja.Label("emit"),
		)
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_openat"))
	instructions = append(instructions,
		readRegisterArgument(asm.R6, syscallArg0Offset, asm.RFP, tempValue, recordStart+fdOffset, asm.Word)...,
	)
	instructions = append(instructions,
		readPathArgument(asm.R6, syscallArg1Offset, asm.RFP, tempValue, recordStart+pathOffset)...,
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, syscallArg2Offset, asm.RFP, tempValue, recordStart+flagsOffset, asm.DWord)...,
	)
	instructions = append(instructions, asm.Ja.Label("emit"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("capture_openat2"))
	instructions = append(instructions,
		readRegisterArgument(asm.R6, syscallArg0Offset, asm.RFP, tempValue, recordStart+fdOffset, asm.Word)...,
	)
	instructions = append(instructions,
		readPathArgument(asm.R6, syscallArg1Offset, asm.RFP, tempValue, recordStart+pathOffset)...,
	)
	instructions = append(instructions,
		asm.LoadMem(asm.R3, asm.R6, 0, asm.DWord),
		asm.Add.Imm(asm.R3, syscallArg2Offset),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(tempPointer)),
		asm.Mov.Imm(asm.R2, 8),
		asm.FnProbeReadKernel.Call(),
		asm.LoadMem(asm.R3, asm.RFP, tempPointer, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(tempValue)),
		asm.Mov.Imm(asm.R2, 8),
		asm.FnProbeReadUser.Call(),
		asm.LoadMem(asm.R7, asm.RFP, tempValue, asm.DWord),
		asm.StoreMem(asm.RFP, recordStart+flagsOffset, asm.R7, asm.DWord),
	)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("emit"),
	)
	instructions = append(instructions, storePendingSyscall(pendingFD, keyOffset, recordStart)...)
	instructions = append(instructions, countCorrelationDrop(correlationDropCounterFD, tempValue)...)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)

	return &cebpf.ProgramSpec{Name: "rg_sread_enter", Type: cebpf.RawTracepoint, License: "GPL", Instructions: instructions}
}

func sensitiveReadExitProgramSpec(ringBufferFD, dropCounterFD, pendingFD int) *cebpf.ProgramSpec {
	const (
		completionTimestampOffset = int16(8)
		returnValueOffset         = int16(16)
	)
	return completedSyscallProgramSpec(
		"rg_sread_exit",
		ringBufferFD,
		dropCounterFD,
		pendingFD,
		int16(binary.Size(sensitiveReadRecord{})),
		completionTimestampOffset,
		returnValueOffset,
	)
}

func decodeSensitiveReadRecord(raw []byte) (sensitiveReadRecord, error) {
	var decoded sensitiveReadRecord
	if len(raw) != binary.Size(decoded) {
		return decoded, fmt.Errorf("decode sensitive read record: size %d, want %d", len(raw), binary.Size(decoded))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &decoded); err != nil {
		return decoded, fmt.Errorf("decode sensitive read record: %w", err)
	}
	return decoded, nil
}

func (collector *SensitiveReadCollector) normalize(raw sensitiveReadRecord) (events.Event, bool) {
	if !openFlagsReadable(raw.Flags) {
		return events.Event{}, false
	}
	pid := int(raw.PID)
	path := resolveProcPath(collector.procRoot, pid, int(raw.FD), cString(raw.FilePath[:]))
	if path == "" || !isSensitiveReadPath(path) {
		return events.Event{}, false
	}

	timestamp := time.Now().UTC()
	ppid := readProcPPID(collector.procRoot, pid)
	executablePath := readProcExe(collector.procRoot, pid)
	processName := cString(raw.Comm[:])
	if executablePath != "" {
		processName = filepath.Base(executablePath)
	}
	event := events.Event{
		EventID:           fmt.Sprintf("sensitive-read-%d-%d-%d", timestamp.UnixNano(), pid, collector.sequence.Add(1)),
		Timestamp:         timestamp,
		Host:              collector.host,
		PID:               pid,
		PPID:              ppid,
		UID:               int(raw.UID),
		ProcessName:       processName,
		ParentProcessName: readProcComm(collector.procRoot, ppid),
		EventType:         events.TypeSensitiveRead,
		ExecutablePath:    executablePath,
		CWD:               readProcCWD(collector.procRoot, pid),
		FilePath:          path,
		Metadata: map[string]any{
			"source":                         "ebpf_raw_tracepoint_sys_exit",
			"kernel_timestamp_ns":            raw.KernelTimestampNS,
			"completion_kernel_timestamp_ns": raw.CompletionKernelTimestampNS,
			"syscall":                        sensitiveReadSyscallName(raw.Syscall),
			"flags":                          raw.Flags,
			"access_mode":                    openAccessMode(raw.Flags),
			"return_value":                   raw.ReturnValue,
			"errno":                          syscallErrno(raw.ReturnValue),
			"outcome":                        syscallOutcome(raw.ReturnValue),
		},
	}
	enrichContainerMetadata(&event, collector.procRoot, pid, collector.containerCache)
	return event, true
}

func openFlagsReadable(flags uint64) bool {
	return flags&openAccessModeMask != openWriteOnly
}

func openAccessMode(flags uint64) string {
	switch flags & openAccessModeMask {
	case openWriteOnly:
		return "write_only"
	case 2:
		return "read_write"
	default:
		return "read_only"
	}
}

func sensitiveReadSyscallName(number uint32) string {
	if hasOpenSyscall && number == openSyscallNumber {
		return "open"
	}
	switch number {
	case openatSyscallNumber:
		return "openat"
	case openat2SyscallNumber:
		return "openat2"
	default:
		return "unknown"
	}
}

func isSensitiveReadPath(path string) bool {
	cleaned := filepath.Clean(path)
	switch cleaned {
	case "/etc/passwd", "/etc/shadow", "/etc/sudoers",
		"/root/.ssh/id_rsa", "/root/.ssh/id_ed25519",
		"/root/.aws/credentials", "/root/.docker/config.json":
		return true
	}
	return strings.HasPrefix(cleaned, "/etc/sudoers.d/") ||
		strings.HasPrefix(cleaned, "/etc/ssh/") ||
		strings.HasPrefix(cleaned, "/root/.ssh/") ||
		strings.HasPrefix(cleaned, "/root/.gnupg/") ||
		strings.HasSuffix(cleaned, "/.ssh/id_rsa") ||
		strings.HasSuffix(cleaned, "/.ssh/id_ed25519") ||
		strings.HasSuffix(cleaned, "/.aws/credentials") ||
		strings.HasSuffix(cleaned, "/.docker/config.json") ||
		strings.HasSuffix(cleaned, "/.kube/config") ||
		strings.Contains(cleaned, "/secrets/")
}
