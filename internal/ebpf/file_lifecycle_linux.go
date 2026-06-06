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
	"sync/atomic"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	"tracejutsu/internal/events"
)

const lifecyclePathSize = 128

type FileLifecycleCollector struct {
	host           string
	procRoot       string
	containerCache *containerMetadataCache
	ringBufferSize int
	metrics        collectorMetrics
	sequence       atomic.Uint64
}

type fileLifecycleRecord struct {
	KernelTimestampNS           uint64
	CompletionKernelTimestampNS uint64
	ReturnValue                 int64
	PID                         uint32
	UID                         uint32
	Comm                        [commSize]byte
	SourcePath                  [lifecyclePathSize]byte
	TargetPath                  [lifecyclePathSize]byte
	SourceFD                    int32
	TargetFD                    int32
	Syscall                     uint32
	_                           uint32
}

func NewFileLifecycleCollector() (*FileLifecycleCollector, error) {
	return NewFileLifecycleCollectorWithConfig(RuntimeConfig{})
}

func NewFileLifecycleCollectorWithConfig(config RuntimeConfig) (*FileLifecycleCollector, error) {
	config, err := checkedRuntimeConfig(config)
	if err != nil {
		return nil, err
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}
	return &FileLifecycleCollector{
		host:           host,
		procRoot:       "/proc",
		containerCache: newContainerMetadataCache(),
		ringBufferSize: config.RingBufferSize,
	}, nil
}

func (collector *FileLifecycleCollector) Run(ctx context.Context, sink chan<- events.Event) error {
	if sink == nil {
		return errors.New("event sink is required")
	}
	_ = rlimit.RemoveMemlock()

	records, err := cebpf.NewMap(&cebpf.MapSpec{Type: cebpf.RingBuf, Name: "rg_life_rb", MaxEntries: uint32(collector.ringBufferSize)})
	if err != nil {
		return fmt.Errorf("create file lifecycle ring buffer: %w", err)
	}
	defer records.Close()

	pending, err := newPendingSyscallMap("rg_life_pending", binary.Size(fileLifecycleRecord{}))
	if err != nil {
		return fmt.Errorf("create pending file lifecycle map: %w", err)
	}
	defer pending.Close()

	drops, err := newDropCounterMap("rg_life_drop")
	if err != nil {
		return fmt.Errorf("create file lifecycle drop counter: %w", err)
	}
	defer drops.Close()
	collector.metrics.attachDropCounter(drops)
	defer collector.metrics.detachDropCounter(drops)

	correlationDrops, err := newDropCounterMap("rg_life_cd")
	if err != nil {
		return fmt.Errorf("create file lifecycle correlation drop counter: %w", err)
	}
	defer correlationDrops.Close()
	collector.metrics.attachCorrelationDropCounter(correlationDrops)
	defer collector.metrics.detachCorrelationDropCounter(correlationDrops)

	enterProgram, err := cebpf.NewProgram(fileLifecycleEnterProgramSpec(pending.FD(), correlationDrops.FD()))
	if err != nil {
		return fmt.Errorf("load file lifecycle sys_enter raw tracepoint program: %w", err)
	}
	defer enterProgram.Close()

	enterHook, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: enterProgram})
	if err != nil {
		return fmt.Errorf("attach sys_enter raw tracepoint: %w", err)
	}
	defer enterHook.Close()

	exitProgram, err := cebpf.NewProgram(fileLifecycleExitProgramSpec(records.FD(), drops.FD(), pending.FD()))
	if err != nil {
		return fmt.Errorf("load file lifecycle sys_exit raw tracepoint program: %w", err)
	}
	defer exitProgram.Close()

	exitHook, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_exit", Program: exitProgram})
	if err != nil {
		return fmt.Errorf("attach sys_exit raw tracepoint: %w", err)
	}
	defer exitHook.Close()

	reader, err := ringbuf.NewReader(records)
	if err != nil {
		return fmt.Errorf("open file lifecycle ring buffer reader: %w", err)
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
			return fmt.Errorf("read file lifecycle ring buffer: %w", err)
		}
		raw, err := decodeFileLifecycleRecord(record.RawSample)
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

func (collector *FileLifecycleCollector) Stats() Stats {
	return collector.metrics.stats()
}

func (*FileLifecycleCollector) Name() string {
	return CollectorFileLifecycle
}

func fileLifecycleEnterProgramSpec(pendingFD, correlationDropCounterFD int) *cebpf.ProgramSpec {
	const (
		pidOffset        = int16(24)
		uidOffset        = int16(28)
		commOffset       = int16(32)
		sourcePathOffset = int16(48)
		targetPathOffset = int16(176)
		sourceFDOffset   = int16(304)
		targetFDOffset   = int16(308)
		syscallOffset    = int16(312)
	)
	recordSize := int16(binary.Size(fileLifecycleRecord{}))
	recordStart := -recordSize
	keyOffset := recordStart - 8
	tempValue := keyOffset - 8

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord),
	}
	if hasLegacyPathSyscalls {
		instructions = append(instructions,
			asm.JEq.Imm(asm.R8, renameSyscallNumber, "legacy_two_path"),
			asm.JEq.Imm(asm.R8, linkSyscallNumber, "legacy_two_path"),
			asm.JEq.Imm(asm.R8, symlinkSyscallNumber, "legacy_two_path"),
			asm.JEq.Imm(asm.R8, unlinkSyscallNumber, "legacy_one_path"),
			asm.JEq.Imm(asm.R8, mkdirSyscallNumber, "legacy_one_path"),
		)
	}
	instructions = append(instructions,
		asm.JEq.Imm(asm.R8, truncateSyscallNumber, "legacy_one_path"),
		asm.JEq.Imm(asm.R8, ftruncateSyscallNumber, "fd_only"),
		asm.JEq.Imm(asm.R8, mkdiratSyscallNumber, "at_one_path"),
		asm.JEq.Imm(asm.R8, unlinkatSyscallNumber, "at_one_path"),
		asm.JEq.Imm(asm.R8, symlinkatSyscallNumber, "symlinkat_path"),
		asm.JEq.Imm(asm.R8, linkatSyscallNumber, "at_two_path"),
		asm.JEq.Imm(asm.R8, renameatSyscallNumber, "at_two_path"),
		asm.JEq.Imm(asm.R8, renameat2SyscallNumber, "at_two_path"),
		asm.Ja.Label("exit"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("init"),
	)
	for offset := recordStart; offset < 0; offset += 8 {
		instructions = append(instructions, asm.StoreMem(asm.RFP, offset, asm.R0, asm.DWord))
	}
	instructions = append(instructions,
		asm.StoreMem(asm.RFP, recordStart+syscallOffset, asm.R8, asm.Word),
		asm.Mov.Imm(asm.R7, atFDCWD),
		asm.StoreMem(asm.RFP, recordStart+sourceFDOffset, asm.R7, asm.Word),
		asm.StoreMem(asm.RFP, recordStart+targetFDOffset, asm.R7, asm.Word),
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
	if hasLegacyPathSyscalls {
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("legacy_two_path"))
		instructions = append(instructions,
			readPathArgumentSized(asm.R6, syscallArg0Offset, asm.RFP, tempValue, recordStart+sourcePathOffset, lifecyclePathSize)...,
		)
		instructions = append(instructions,
			readPathArgumentSized(asm.R6, syscallArg1Offset, asm.RFP, tempValue, recordStart+targetPathOffset, lifecyclePathSize)...,
		)
		instructions = append(instructions, asm.Ja.Label("emit"))
		instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("legacy_one_path"))
		instructions = append(instructions,
			readPathArgumentSized(asm.R6, syscallArg0Offset, asm.RFP, tempValue, recordStart+sourcePathOffset, lifecyclePathSize)...,
		)
		instructions = append(instructions, asm.Ja.Label("emit"))
	}
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("fd_only"))
	instructions = append(instructions,
		readRegisterArgument(asm.R6, syscallArg0Offset, asm.RFP, tempValue, recordStart+sourceFDOffset, asm.Word)...,
	)
	instructions = append(instructions, asm.Ja.Label("emit"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("at_one_path"))
	instructions = append(instructions,
		readRegisterArgument(asm.R6, syscallArg0Offset, asm.RFP, tempValue, recordStart+sourceFDOffset, asm.Word)...,
	)
	instructions = append(instructions,
		readPathArgumentSized(asm.R6, syscallArg1Offset, asm.RFP, tempValue, recordStart+sourcePathOffset, lifecyclePathSize)...,
	)
	instructions = append(instructions, asm.Ja.Label("emit"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("symlinkat_path"))
	instructions = append(instructions,
		readPathArgumentSized(asm.R6, syscallArg0Offset, asm.RFP, tempValue, recordStart+sourcePathOffset, lifecyclePathSize)...,
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, syscallArg1Offset, asm.RFP, tempValue, recordStart+targetFDOffset, asm.Word)...,
	)
	instructions = append(instructions,
		readPathArgumentSized(asm.R6, syscallArg2Offset, asm.RFP, tempValue, recordStart+targetPathOffset, lifecyclePathSize)...,
	)
	instructions = append(instructions, asm.Ja.Label("emit"))
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("at_two_path"))
	instructions = append(instructions,
		readRegisterArgument(asm.R6, syscallArg0Offset, asm.RFP, tempValue, recordStart+sourceFDOffset, asm.Word)...,
	)
	instructions = append(instructions,
		readPathArgumentSized(asm.R6, syscallArg1Offset, asm.RFP, tempValue, recordStart+sourcePathOffset, lifecyclePathSize)...,
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, syscallArg2Offset, asm.RFP, tempValue, recordStart+targetFDOffset, asm.Word)...,
	)
	instructions = append(instructions,
		readPathArgumentSized(asm.R6, syscallArg3Offset, asm.RFP, tempValue, recordStart+targetPathOffset, lifecyclePathSize)...,
	)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("emit"),
	)
	instructions = append(instructions, storePendingSyscall(pendingFD, keyOffset, recordStart)...)
	instructions = append(instructions, countCorrelationDrop(correlationDropCounterFD, tempValue)...)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
	return &cebpf.ProgramSpec{Name: "rg_life_enter", Type: cebpf.RawTracepoint, License: "GPL", Instructions: instructions}
}

func fileLifecycleExitProgramSpec(ringBufferFD, dropCounterFD, pendingFD int) *cebpf.ProgramSpec {
	const (
		completionTimestampOffset = int16(8)
		returnValueOffset         = int16(16)
	)
	return completedSyscallProgramSpec("rg_life_exit", ringBufferFD, dropCounterFD, pendingFD, int16(binary.Size(fileLifecycleRecord{})), completionTimestampOffset, returnValueOffset)
}

func decodeFileLifecycleRecord(raw []byte) (fileLifecycleRecord, error) {
	var decoded fileLifecycleRecord
	if len(raw) != binary.Size(decoded) {
		return decoded, fmt.Errorf("decode file lifecycle record: size %d, want %d", len(raw), binary.Size(decoded))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &decoded); err != nil {
		return decoded, fmt.Errorf("decode file lifecycle record: %w", err)
	}
	return decoded, nil
}

func (collector *FileLifecycleCollector) normalize(raw fileLifecycleRecord) (events.Event, bool) {
	pid := int(raw.PID)
	sourcePath := resolveLifecyclePath(collector.procRoot, pid, int(raw.SourceFD), cString(raw.SourcePath[:]))
	targetPath := resolveLifecyclePath(collector.procRoot, pid, int(raw.TargetFD), cString(raw.TargetPath[:]))
	primaryPath := fileLifecyclePrimaryPath(raw.Syscall, sourcePath, targetPath)
	if primaryPath == "" {
		return events.Event{}, false
	}

	timestamp := time.Now().UTC()
	ppid := readProcPPID(collector.procRoot, pid)
	executablePath := readProcExe(collector.procRoot, pid)
	processName := cString(raw.Comm[:])
	if executablePath != "" {
		processName = filepath.Base(executablePath)
	}
	metadata := map[string]any{
		"source":                         "ebpf_raw_tracepoint_sys_exit",
		"kernel_timestamp_ns":            raw.KernelTimestampNS,
		"completion_kernel_timestamp_ns": raw.CompletionKernelTimestampNS,
		"syscall":                        fileLifecycleSyscallName(raw.Syscall),
		"action":                         fileLifecycleAction(raw.Syscall),
		"return_value":                   raw.ReturnValue,
		"errno":                          syscallErrno(raw.ReturnValue),
		"outcome":                        syscallOutcome(raw.ReturnValue),
	}
	if sourcePath != "" {
		metadata["source_path"] = sourcePath
	}
	if targetPath != "" {
		metadata["target_path"] = targetPath
	}
	event := events.Event{
		EventID:           fmt.Sprintf("file-lifecycle-%d-%d-%d", timestamp.UnixNano(), pid, collector.sequence.Add(1)),
		Timestamp:         timestamp,
		Host:              collector.host,
		PID:               pid,
		PPID:              ppid,
		UID:               int(raw.UID),
		ProcessName:       processName,
		ParentProcessName: readProcComm(collector.procRoot, ppid),
		EventType:         events.TypeFileLifecycle,
		ExecutablePath:    executablePath,
		CWD:               readProcCWD(collector.procRoot, pid),
		FilePath:          primaryPath,
		Metadata:          metadata,
	}
	enrichContainerMetadata(&event, collector.procRoot, pid, collector.containerCache)
	return event, true
}

func resolveLifecyclePath(procRoot string, pid, dirfd int, path string) string {
	if path != "" {
		return resolveProcPath(procRoot, pid, dirfd, path)
	}
	return readProcFD(procRoot, pid, dirfd)
}

func fileLifecyclePrimaryPath(syscall uint32, sourcePath, targetPath string) string {
	switch fileLifecycleAction(syscall) {
	case "rename", "link", "symlink":
		if targetPath != "" {
			return targetPath
		}
	}
	return sourcePath
}

func fileLifecycleAction(number uint32) string {
	switch number {
	case renameSyscallNumber, renameatSyscallNumber, renameat2SyscallNumber:
		return "rename"
	case unlinkSyscallNumber, unlinkatSyscallNumber:
		return "unlink"
	case mkdirSyscallNumber, mkdiratSyscallNumber:
		return "mkdir"
	case symlinkSyscallNumber, symlinkatSyscallNumber:
		return "symlink"
	case linkSyscallNumber, linkatSyscallNumber:
		return "link"
	case truncateSyscallNumber, ftruncateSyscallNumber:
		return "truncate"
	default:
		return "unknown"
	}
}

func fileLifecycleSyscallName(number uint32) string {
	switch number {
	case renameSyscallNumber:
		return "rename"
	case renameatSyscallNumber:
		return "renameat"
	case renameat2SyscallNumber:
		return "renameat2"
	case unlinkSyscallNumber:
		return "unlink"
	case unlinkatSyscallNumber:
		return "unlinkat"
	case mkdirSyscallNumber:
		return "mkdir"
	case mkdiratSyscallNumber:
		return "mkdirat"
	case symlinkSyscallNumber:
		return "symlink"
	case symlinkatSyscallNumber:
		return "symlinkat"
	case linkSyscallNumber:
		return "link"
	case linkatSyscallNumber:
		return "linkat"
	case truncateSyscallNumber:
		return "truncate"
	case ftruncateSyscallNumber:
		return "ftruncate"
	default:
		return "unknown"
	}
}
