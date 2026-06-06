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

type BehaviorSyscallCollector struct {
	host           string
	procRoot       string
	containerCache *containerMetadataCache
	ringBufferSize int
	name           string
	bpfName        string
	eventType      events.Type
	syscalls       map[uint32]string
	metrics        collectorMetrics
	sequence       atomic.Uint64
}

type behaviorSyscallRecord struct {
	KernelTimestampNS           uint64
	CompletionKernelTimestampNS uint64
	ReturnValue                 int64
	PID                         uint32
	UID                         uint32
	Comm                        [commSize]byte
	Syscall                     uint32
	_                           uint32
	Args                        [3]uint64
}

func NewPrivilegeChangeCollector() (*BehaviorSyscallCollector, error) {
	return NewPrivilegeChangeCollectorWithConfig(RuntimeConfig{})
}

func NewPrivilegeChangeCollectorWithConfig(config RuntimeConfig) (*BehaviorSyscallCollector, error) {
	return newBehaviorSyscallCollector(config, CollectorPrivilegeChange, "privchg", events.TypePrivilegeChange, map[uint32]string{
		setuidSyscallNumber:    "setuid",
		setgidSyscallNumber:    "setgid",
		setreuidSyscallNumber:  "setreuid",
		setregidSyscallNumber:  "setregid",
		setgroupsSyscallNumber: "setgroups",
		setresuidSyscallNumber: "setresuid",
		setresgidSyscallNumber: "setresgid",
		capsetSyscallNumber:    "capset",
		prctlSyscallNumber:     "prctl",
	})
}

func NewNamespaceChangeCollector() (*BehaviorSyscallCollector, error) {
	return NewNamespaceChangeCollectorWithConfig(RuntimeConfig{})
}

func NewNamespaceChangeCollectorWithConfig(config RuntimeConfig) (*BehaviorSyscallCollector, error) {
	return newBehaviorSyscallCollector(config, CollectorNamespaceChange, "nschg", events.TypeNamespaceChange, map[uint32]string{
		setnsSyscallNumber:     "setns",
		unshareSyscallNumber:   "unshare",
		mountSyscallNumber:     "mount",
		umount2SyscallNumber:   "umount2",
		pivotRootSyscallNumber: "pivot_root",
		chrootSyscallNumber:    "chroot",
	})
}

func NewProcessAccessCollector() (*BehaviorSyscallCollector, error) {
	return NewProcessAccessCollectorWithConfig(RuntimeConfig{})
}

func NewProcessAccessCollectorWithConfig(config RuntimeConfig) (*BehaviorSyscallCollector, error) {
	return newBehaviorSyscallCollector(config, CollectorProcessAccess, "procacc", events.TypeProcessAccess, map[uint32]string{
		ptraceSyscallNumber:          "ptrace",
		processVMReadvSyscallNumber:  "process_vm_readv",
		processVMWritevSyscallNumber: "process_vm_writev",
	})
}

func NewKernelTamperCollector() (*BehaviorSyscallCollector, error) {
	return NewKernelTamperCollectorWithConfig(RuntimeConfig{})
}

func NewKernelTamperCollectorWithConfig(config RuntimeConfig) (*BehaviorSyscallCollector, error) {
	return newBehaviorSyscallCollector(config, CollectorKernelTamper, "kerntmp", events.TypeKernelTamper, map[uint32]string{
		bpfSyscallNumber:          "bpf",
		initModuleSyscallNumber:   "init_module",
		finitModuleSyscallNumber:  "finit_module",
		deleteModuleSyscallNumber: "delete_module",
		kexecLoadSyscallNumber:    "kexec_load",
	})
}

func newBehaviorSyscallCollector(config RuntimeConfig, name, bpfName string, eventType events.Type, syscalls map[uint32]string) (*BehaviorSyscallCollector, error) {
	config, err := checkedRuntimeConfig(config)
	if err != nil {
		return nil, err
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}
	return &BehaviorSyscallCollector{
		host:           host,
		procRoot:       "/proc",
		containerCache: newContainerMetadataCache(),
		ringBufferSize: config.RingBufferSize,
		name:           name,
		bpfName:        bpfName,
		eventType:      eventType,
		syscalls:       syscalls,
	}, nil
}

func (collector *BehaviorSyscallCollector) Run(ctx context.Context, sink chan<- events.Event) error {
	if sink == nil {
		return errors.New("event sink is required")
	}
	_ = rlimit.RemoveMemlock()

	records, err := cebpf.NewMap(&cebpf.MapSpec{Type: cebpf.RingBuf, Name: "rg_" + collector.bpfName + "_rb", MaxEntries: uint32(collector.ringBufferSize)})
	if err != nil {
		return fmt.Errorf("create %s ring buffer: %w", collector.name, err)
	}
	defer records.Close()

	pending, err := newPendingSyscallMap("rg_"+collector.bpfName+"_pend", binary.Size(behaviorSyscallRecord{}))
	if err != nil {
		return fmt.Errorf("create pending %s map: %w", collector.name, err)
	}
	defer pending.Close()

	drops, err := newDropCounterMap("rg_" + collector.bpfName + "_drop")
	if err != nil {
		return fmt.Errorf("create %s drop counter: %w", collector.name, err)
	}
	defer drops.Close()
	collector.metrics.attachDropCounter(drops)
	defer collector.metrics.detachDropCounter(drops)

	correlationDrops, err := newDropCounterMap("rg_" + collector.bpfName + "_cd")
	if err != nil {
		return fmt.Errorf("create %s correlation drop counter: %w", collector.name, err)
	}
	defer correlationDrops.Close()
	collector.metrics.attachCorrelationDropCounter(correlationDrops)
	defer collector.metrics.detachCorrelationDropCounter(correlationDrops)

	enterProgram, err := cebpf.NewProgram(behaviorSyscallEnterProgramSpec(collector.bpfName, collector.syscallNumbers(), pending.FD(), correlationDrops.FD()))
	if err != nil {
		return fmt.Errorf("load %s sys_enter raw tracepoint program: %w", collector.name, err)
	}
	defer enterProgram.Close()

	enterHook, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_enter", Program: enterProgram})
	if err != nil {
		return fmt.Errorf("attach sys_enter raw tracepoint: %w", err)
	}
	defer enterHook.Close()

	exitProgram, err := cebpf.NewProgram(behaviorSyscallExitProgramSpec(collector.bpfName, records.FD(), drops.FD(), pending.FD()))
	if err != nil {
		return fmt.Errorf("load %s sys_exit raw tracepoint program: %w", collector.name, err)
	}
	defer exitProgram.Close()

	exitHook, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sys_exit", Program: exitProgram})
	if err != nil {
		return fmt.Errorf("attach sys_exit raw tracepoint: %w", err)
	}
	defer exitHook.Close()

	reader, err := ringbuf.NewReader(records)
	if err != nil {
		return fmt.Errorf("open %s ring buffer reader: %w", collector.name, err)
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
			return fmt.Errorf("read %s ring buffer: %w", collector.name, err)
		}
		raw, err := decodeBehaviorSyscallRecord(record.RawSample)
		if err != nil {
			return err
		}
		event := collector.normalize(raw)
		select {
		case sink <- event:
		case <-ctx.Done():
			return nil
		}
	}
}

func (collector *BehaviorSyscallCollector) Stats() Stats {
	return collector.metrics.stats()
}

func (collector *BehaviorSyscallCollector) Name() string {
	return collector.name
}

func (collector *BehaviorSyscallCollector) syscallNumbers() []uint32 {
	numbers := make([]uint32, 0, len(collector.syscalls))
	for number := range collector.syscalls {
		numbers = append(numbers, number)
	}
	return numbers
}

func behaviorSyscallEnterProgramSpec(name string, syscalls []uint32, pendingFD, correlationDropCounterFD int) *cebpf.ProgramSpec {
	const (
		pidOffset     = int16(24)
		uidOffset     = int16(28)
		commOffset    = int16(32)
		syscallOffset = int16(48)
		arg0Offset    = int16(56)
		arg1Offset    = int16(64)
		arg2Offset    = int16(72)
	)
	recordSize := int16(binary.Size(behaviorSyscallRecord{}))
	recordStart := -recordSize
	keyOffset := recordStart - 8
	tempValue := keyOffset - 8

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord),
	}
	for _, syscall := range syscalls {
		instructions = append(instructions, asm.JEq.Imm(asm.R8, int32(syscall), "capture"))
	}
	instructions = append(instructions,
		asm.Ja.Label("exit"),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("capture"),
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
	instructions = append(instructions,
		readRegisterArgument(asm.R6, syscallArg0Offset, asm.RFP, tempValue, recordStart+arg0Offset, asm.DWord)...,
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, syscallArg1Offset, asm.RFP, tempValue, recordStart+arg1Offset, asm.DWord)...,
	)
	instructions = append(instructions,
		readRegisterArgument(asm.R6, syscallArg2Offset, asm.RFP, tempValue, recordStart+arg2Offset, asm.DWord)...,
	)
	instructions = append(instructions, storePendingSyscall(pendingFD, keyOffset, recordStart)...)
	instructions = append(instructions, countCorrelationDrop(correlationDropCounterFD, tempValue)...)
	instructions = append(instructions, asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"), asm.Return())
	return &cebpf.ProgramSpec{Name: "rg_" + name + "_enter", Type: cebpf.RawTracepoint, License: "GPL", Instructions: instructions}
}

func behaviorSyscallExitProgramSpec(name string, ringBufferFD, dropCounterFD, pendingFD int) *cebpf.ProgramSpec {
	const (
		completionTimestampOffset = int16(8)
		returnValueOffset         = int16(16)
	)
	return completedSyscallProgramSpec("rg_"+name+"_exit", ringBufferFD, dropCounterFD, pendingFD, int16(binary.Size(behaviorSyscallRecord{})), completionTimestampOffset, returnValueOffset)
}

func decodeBehaviorSyscallRecord(raw []byte) (behaviorSyscallRecord, error) {
	var decoded behaviorSyscallRecord
	if len(raw) != binary.Size(decoded) {
		return decoded, fmt.Errorf("decode behavior syscall record: size %d, want %d", len(raw), binary.Size(decoded))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &decoded); err != nil {
		return decoded, fmt.Errorf("decode behavior syscall record: %w", err)
	}
	return decoded, nil
}

func (collector *BehaviorSyscallCollector) normalize(raw behaviorSyscallRecord) events.Event {
	timestamp := time.Now().UTC()
	pid := int(raw.PID)
	ppid := readProcPPID(collector.procRoot, pid)
	executablePath := readProcExe(collector.procRoot, pid)
	processName := cString(raw.Comm[:])
	if executablePath != "" {
		processName = filepath.Base(executablePath)
	}
	syscallName := collector.syscalls[raw.Syscall]
	metadata := map[string]any{
		"source":                         "ebpf_raw_tracepoint_sys_exit",
		"kernel_timestamp_ns":            raw.KernelTimestampNS,
		"completion_kernel_timestamp_ns": raw.CompletionKernelTimestampNS,
		"syscall":                        syscallName,
		"arg0":                           raw.Args[0],
		"arg1":                           raw.Args[1],
		"arg2":                           raw.Args[2],
		"return_value":                   raw.ReturnValue,
		"errno":                          syscallErrno(raw.ReturnValue),
		"outcome":                        syscallOutcome(raw.ReturnValue),
	}
	if targetPID, ok := behaviorTargetPID(collector.eventType, raw); ok {
		metadata["target_pid"] = targetPID
	}
	event := events.Event{
		EventID:           fmt.Sprintf("%s-%d-%d-%d", collector.name, timestamp.UnixNano(), pid, collector.sequence.Add(1)),
		Timestamp:         timestamp,
		Host:              collector.host,
		PID:               pid,
		PPID:              ppid,
		UID:               int(raw.UID),
		ProcessName:       processName,
		ParentProcessName: readProcComm(collector.procRoot, ppid),
		EventType:         collector.eventType,
		ExecutablePath:    executablePath,
		CWD:               readProcCWD(collector.procRoot, pid),
		Metadata:          metadata,
	}
	enrichContainerMetadata(&event, collector.procRoot, pid, collector.containerCache)
	return event
}

func behaviorTargetPID(eventType events.Type, raw behaviorSyscallRecord) (uint64, bool) {
	if eventType != events.TypeProcessAccess {
		return 0, false
	}
	switch raw.Syscall {
	case ptraceSyscallNumber:
		return raw.Args[1], true
	case processVMReadvSyscallNumber, processVMWritevSyscallNumber:
		return raw.Args[0], true
	default:
		return 0, false
	}
}
