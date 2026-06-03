//go:build linux && amd64

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

	"runtime-guard/internal/events"
)

const (
	chmodSyscallNumber     = 90
	fchmodSyscallNumber    = 91
	fchmodatSyscallNumber  = 268
	fchmodat2SyscallNumber = 452
	atFDCWD                = -100
)

type ChmodCollector struct {
	host           string
	procRoot       string
	containerCache *containerMetadataCache
	ringBufferSize int
	metrics        collectorMetrics
	sequence       atomic.Uint64
}

type chmodRecord struct {
	KernelTimestampNS           uint64
	CompletionKernelTimestampNS uint64
	ReturnValue                 int64
	PID                         uint32
	UID                         uint32
	Comm                        [commSize]byte
	FilePath                    [filenameSize]byte
	FD                          int32
	Mode                        uint32
	Syscall                     uint32
	_                           uint32
}

func NewChmodCollector() (*ChmodCollector, error) {
	return NewChmodCollectorWithConfig(RuntimeConfig{})
}

func NewChmodCollectorWithConfig(config RuntimeConfig) (*ChmodCollector, error) {
	config, err := checkedRuntimeConfig(config)
	if err != nil {
		return nil, err
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}
	return &ChmodCollector{
		host:           host,
		procRoot:       "/proc",
		containerCache: newContainerMetadataCache(),
		ringBufferSize: config.RingBufferSize,
	}, nil
}

// Run emits normalized completed chmod operations. The execute-bit signal
// describes the requested mode; it does not prove whether the bit was newly
// added.
func (collector *ChmodCollector) Run(ctx context.Context, sink chan<- events.Event) error {
	if sink == nil {
		return errors.New("event sink is required")
	}
	_ = rlimit.RemoveMemlock()

	records, err := cebpf.NewMap(&cebpf.MapSpec{
		Type:       cebpf.RingBuf,
		Name:       "rg_chmod_rb",
		MaxEntries: uint32(collector.ringBufferSize),
	})
	if err != nil {
		return fmt.Errorf("create chmod ring buffer: %w", err)
	}
	defer records.Close()

	pending, err := newPendingSyscallMap("rg_ch_pending", binary.Size(chmodRecord{}))
	if err != nil {
		return fmt.Errorf("create pending chmod map: %w", err)
	}
	defer pending.Close()

	drops, err := newDropCounterMap("rg_chmod_drop")
	if err != nil {
		return fmt.Errorf("create chmod drop counter: %w", err)
	}
	defer drops.Close()
	collector.metrics.attachDropCounter(drops)
	defer collector.metrics.detachDropCounter(drops)

	correlationDrops, err := newDropCounterMap("rg_ch_corr_drop")
	if err != nil {
		return fmt.Errorf("create chmod correlation drop counter: %w", err)
	}
	defer correlationDrops.Close()
	collector.metrics.attachCorrelationDropCounter(correlationDrops)
	defer collector.metrics.detachCorrelationDropCounter(correlationDrops)

	enterProgram, err := cebpf.NewProgram(chmodEnterProgramSpec(pending.FD(), correlationDrops.FD()))
	if err != nil {
		return fmt.Errorf("load chmod sys_enter raw tracepoint program: %w", err)
	}
	defer enterProgram.Close()

	enterHook, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: enterProgram,
	})
	if err != nil {
		return fmt.Errorf("attach sys_enter raw tracepoint: %w", err)
	}
	defer enterHook.Close()

	exitProgram, err := cebpf.NewProgram(chmodExitProgramSpec(records.FD(), drops.FD(), pending.FD()))
	if err != nil {
		return fmt.Errorf("load chmod sys_exit raw tracepoint program: %w", err)
	}
	defer exitProgram.Close()

	exitHook, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: exitProgram,
	})
	if err != nil {
		return fmt.Errorf("attach sys_exit raw tracepoint: %w", err)
	}
	defer exitHook.Close()

	reader, err := ringbuf.NewReader(records)
	if err != nil {
		return fmt.Errorf("open chmod ring buffer reader: %w", err)
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
			return fmt.Errorf("read chmod ring buffer: %w", err)
		}

		raw, err := decodeChmodRecord(record.RawSample)
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

func (collector *ChmodCollector) Stats() Stats {
	return collector.metrics.stats()
}

func (*ChmodCollector) Name() string {
	return "chmod"
}

func chmodEnterProgramSpec(pendingFD, correlationDropCounterFD int) *cebpf.ProgramSpec {
	const (
		pidOffset     = int16(24)
		uidOffset     = int16(28)
		commOffset    = int16(32)
		pathOffset    = int16(48)
		fdOffset      = int16(304)
		modeOffset    = int16(308)
		syscallOffset = int16(312)
	)
	recordSize := int16(binary.Size(chmodRecord{}))
	recordStart := -recordSize
	keyOffset := recordStart - 8
	tempValue := keyOffset - 8

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord),
		asm.JEq.Imm(asm.R8, chmodSyscallNumber, "capture"),
		asm.JEq.Imm(asm.R8, fchmodSyscallNumber, "capture"),
		asm.JEq.Imm(asm.R8, fchmodatSyscallNumber, "capture"),
		asm.JEq.Imm(asm.R8, fchmodat2SyscallNumber, "capture"),
		asm.Ja.Label("exit"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("capture"),
	}
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

		asm.JEq.Imm(asm.R8, chmodSyscallNumber, "chmod_path"),
		asm.JEq.Imm(asm.R8, fchmodSyscallNumber, "fchmod_fd"),
	)

	// fchmodat and fchmodat2: dirfd, pathname, mode.
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsDIOffset, asm.RFP, tempValue, recordStart+fdOffset, asm.Word)...,
	)
	instructions = append(instructions,
		readPathArgument(asm.R6, ptRegsSIOffset, asm.RFP, tempValue, recordStart+pathOffset)...,
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsDXOffset, asm.RFP, tempValue, recordStart+modeOffset, asm.Word)...,
	)
	instructions = append(instructions, asm.Ja.Label("emit"))

	// chmod: pathname, mode.
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("chmod_path"),
	)
	instructions = append(instructions,
		readPathArgument(asm.R6, ptRegsDIOffset, asm.RFP, tempValue, recordStart+pathOffset)...,
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsSIOffset, asm.RFP, tempValue, recordStart+modeOffset, asm.Word)...,
	)
	instructions = append(instructions, asm.Ja.Label("emit"))

	// fchmod: fd, mode.
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("fchmod_fd"),
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsDIOffset, asm.RFP, tempValue, recordStart+fdOffset, asm.Word)...,
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, ptRegsSIOffset, asm.RFP, tempValue, recordStart+modeOffset, asm.Word)...,
	)

	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("emit"),
	)
	instructions = append(instructions,
		storePendingSyscall(pendingFD, keyOffset, recordStart)...,
	)
	instructions = append(instructions, countCorrelationDrop(correlationDropCounterFD, tempValue)...)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)

	return &cebpf.ProgramSpec{
		Name:         "rg_chmod_enter",
		Type:         cebpf.RawTracepoint,
		License:      "GPL",
		Instructions: instructions,
	}
}

func chmodExitProgramSpec(ringBufferFD, dropCounterFD, pendingFD int) *cebpf.ProgramSpec {
	const (
		completionTimestampOffset = int16(8)
		returnValueOffset         = int16(16)
	)
	return completedSyscallProgramSpec(
		"rg_chmod_exit",
		ringBufferFD,
		dropCounterFD,
		pendingFD,
		int16(binary.Size(chmodRecord{})),
		completionTimestampOffset,
		returnValueOffset,
	)
}

func decodeChmodRecord(raw []byte) (chmodRecord, error) {
	var decoded chmodRecord
	if len(raw) != binary.Size(decoded) {
		return decoded, fmt.Errorf("decode chmod record: size %d, want %d", len(raw), binary.Size(decoded))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &decoded); err != nil {
		return decoded, fmt.Errorf("decode chmod record: %w", err)
	}
	return decoded, nil
}

func (collector *ChmodCollector) normalize(raw chmodRecord) (events.Event, bool) {
	pid := int(raw.PID)
	path := collector.resolvePath(pid, raw)
	if path == "" {
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
		EventID:           fmt.Sprintf("chmod-%d-%d-%d", timestamp.UnixNano(), pid, collector.sequence.Add(1)),
		Timestamp:         timestamp,
		Host:              collector.host,
		PID:               pid,
		PPID:              ppid,
		UID:               int(raw.UID),
		ProcessName:       processName,
		ParentProcessName: readProcComm(collector.procRoot, ppid),
		EventType:         events.TypeChmod,
		ExecutablePath:    executablePath,
		CWD:               readProcCWD(collector.procRoot, pid),
		FilePath:          path,
		Metadata: map[string]any{
			"source":                         "ebpf_raw_tracepoint_sys_exit",
			"kernel_timestamp_ns":            raw.KernelTimestampNS,
			"completion_kernel_timestamp_ns": raw.CompletionKernelTimestampNS,
			"syscall":                        chmodSyscallName(raw.Syscall),
			"mode":                           fmt.Sprintf("%04o", raw.Mode&0o7777),
			"added_execute_bit":              raw.Mode&0o111 != 0,
			"return_value":                   raw.ReturnValue,
			"errno":                          syscallErrno(raw.ReturnValue),
			"outcome":                        syscallOutcome(raw.ReturnValue),
		},
	}
	enrichContainerMetadata(&event, collector.procRoot, pid, collector.containerCache)
	return event, true
}

func (collector *ChmodCollector) resolvePath(pid int, raw chmodRecord) string {
	switch raw.Syscall {
	case chmodSyscallNumber:
		return resolveProcPath(collector.procRoot, pid, atFDCWD, cString(raw.FilePath[:]))
	case fchmodSyscallNumber:
		return readProcFD(collector.procRoot, pid, int(raw.FD))
	case fchmodatSyscallNumber, fchmodat2SyscallNumber:
		return resolveProcPath(collector.procRoot, pid, int(raw.FD), cString(raw.FilePath[:]))
	default:
		return ""
	}
}

func chmodSyscallName(number uint32) string {
	switch number {
	case chmodSyscallNumber:
		return "chmod"
	case fchmodSyscallNumber:
		return "fchmod"
	case fchmodatSyscallNumber:
		return "fchmodat"
	case fchmodat2SyscallNumber:
		return "fchmodat2"
	default:
		return "unknown"
	}
}
