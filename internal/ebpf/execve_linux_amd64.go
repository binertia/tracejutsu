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
	"strconv"
	"strings"
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
	execveSyscallNumber = 59
	ptRegsDIOffset      = 112
	filenameSize        = 256
	commSize            = 16
)

type ExecveCollector struct {
	host           string
	procRoot       string
	containerCache *containerMetadataCache
	ringBufferSize int
	metrics        collectorMetrics
	sequence       atomic.Uint64
}

type execveRecord struct {
	KernelTimestampNS uint64
	PID               uint32
	UID               uint32
	Comm              [commSize]byte
	Filename          [filenameSize]byte
}

func NewExecveCollector() (*ExecveCollector, error) {
	return NewExecveCollectorWithConfig(RuntimeConfig{})
}

func NewExecveCollectorWithConfig(config RuntimeConfig) (*ExecveCollector, error) {
	config, err := checkedRuntimeConfig(config)
	if err != nil {
		return nil, err
	}
	host, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("read hostname: %w", err)
	}
	return &ExecveCollector{
		host:           host,
		procRoot:       "/proc",
		containerCache: newContainerMetadataCache(),
		ringBufferSize: config.RingBufferSize,
	}, nil
}

// Run attaches an amd64 raw tracepoint collector and emits normalized execve
// events until the context is canceled. Reading syscall arguments remains in
// eBPF; slower parent metadata enrichment happens in userspace.
func (collector *ExecveCollector) Run(ctx context.Context, sink chan<- events.Event) error {
	if sink == nil {
		return errors.New("event sink is required")
	}
	// Linux 5.11 and newer account BPF memory through cgroups. Raising
	// RLIMIT_MEMLOCK is still useful on older kernels but is not authoritative.
	_ = rlimit.RemoveMemlock()

	records, err := cebpf.NewMap(&cebpf.MapSpec{
		Type:       cebpf.RingBuf,
		Name:       "rg_execve_rb",
		MaxEntries: uint32(collector.ringBufferSize),
	})
	if err != nil {
		return fmt.Errorf("create execve ring buffer: %w", err)
	}
	defer records.Close()

	drops, err := newDropCounterMap("rg_execve_drop")
	if err != nil {
		return fmt.Errorf("create execve drop counter: %w", err)
	}
	defer drops.Close()
	collector.metrics.attachDropCounter(drops)
	defer collector.metrics.detachDropCounter(drops)

	program, err := cebpf.NewProgram(execveProgramSpec(records.FD(), drops.FD()))
	if err != nil {
		return fmt.Errorf("load execve raw tracepoint program: %w", err)
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
		return fmt.Errorf("open execve ring buffer reader: %w", err)
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
			return fmt.Errorf("read execve ring buffer: %w", err)
		}

		raw, err := decodeExecveRecord(record.RawSample)
		if err != nil {
			return err
		}

		select {
		case sink <- collector.normalize(raw):
		case <-ctx.Done():
			return nil
		}
	}
}

func (collector *ExecveCollector) Stats() Stats {
	return collector.metrics.stats()
}

func (*ExecveCollector) Name() string {
	return "execve"
}

func execveProgramSpec(ringBufferFD, dropCounterFD int) *cebpf.ProgramSpec {
	const (
		commOffset = int16(16)
		fileOffset = int16(32)
	)
	recordSize := int16(binary.Size(execveRecord{}))
	recordStart := -recordSize
	tempPointer := recordStart - 8

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R7, asm.R6, 8, asm.DWord),
		asm.JNE.Imm(asm.R7, execveSyscallNumber, "exit"),
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
		asm.Add.Imm(asm.R1, int32(recordStart+commOffset)),
		asm.Mov.Imm(asm.R2, commSize),
		asm.FnGetCurrentComm.Call(),

		asm.LoadMem(asm.R3, asm.R6, 0, asm.DWord),
		asm.Add.Imm(asm.R3, ptRegsDIOffset),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(tempPointer)),
		asm.Mov.Imm(asm.R2, 8),
		asm.FnProbeReadKernel.Call(),

		asm.LoadMem(asm.R3, asm.RFP, tempPointer, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, int32(recordStart+fileOffset)),
		asm.Mov.Imm(asm.R2, filenameSize),
		asm.FnProbeReadUserStr.Call(),

		asm.LoadMapPtr(asm.R1, ringBufferFD),
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
		Name:         "rg_execve",
		Type:         cebpf.RawTracepoint,
		License:      "GPL",
		Instructions: instructions,
	}
}

func decodeExecveRecord(raw []byte) (execveRecord, error) {
	var decoded execveRecord
	if len(raw) != binary.Size(decoded) {
		return decoded, fmt.Errorf("decode execve record: size %d, want %d", len(raw), binary.Size(decoded))
	}
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &decoded); err != nil {
		return decoded, fmt.Errorf("decode execve record: %w", err)
	}
	return decoded, nil
}

func (collector *ExecveCollector) normalize(raw execveRecord) events.Event {
	timestamp := time.Now().UTC()
	pid := int(raw.PID)
	ppid := readProcPPID(collector.procRoot, pid)
	filename := cString(raw.Filename[:])
	processName := filepath.Base(filename)
	if processName == "." || processName == "" {
		processName = cString(raw.Comm[:])
	}

	var commandLine []string
	if filename != "" {
		commandLine = []string{filename}
	}

	event := events.Event{
		EventID:           fmt.Sprintf("execve-%d-%d-%d", timestamp.UnixNano(), pid, collector.sequence.Add(1)),
		Timestamp:         timestamp,
		Host:              collector.host,
		PID:               pid,
		PPID:              ppid,
		UID:               int(raw.UID),
		ProcessName:       processName,
		ParentProcessName: readProcComm(collector.procRoot, ppid),
		EventType:         events.TypeExecve,
		ExecutablePath:    filename,
		CommandLine:       commandLine,
		CWD:               readProcCWD(collector.procRoot, pid),
		Metadata: map[string]any{
			"source":              "ebpf_raw_tracepoint_sys_enter",
			"kernel_timestamp_ns": raw.KernelTimestampNS,
			"previous_process":    cString(raw.Comm[:]),
		},
	}
	enrichContainerMetadata(&event, collector.procRoot, pid, collector.containerCache)
	return event
}

func readProcPPID(procRoot string, pid int) int {
	contents, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "status"))
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(contents), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return 0
		}
		ppid, err := strconv.Atoi(fields[1])
		if err != nil {
			return 0
		}
		return ppid
	}
	return 0
}

func readProcComm(procRoot string, pid int) string {
	if pid <= 0 {
		return ""
	}
	contents, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(contents))
}

func readProcCWD(procRoot string, pid int) string {
	if pid <= 0 {
		return ""
	}
	cwd, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "cwd"))
	if err != nil {
		return ""
	}
	return cwd
}

func readProcExe(procRoot string, pid int) string {
	if pid <= 0 {
		return ""
	}
	executable, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return executable
}

func cString(raw []byte) string {
	if end := bytes.IndexByte(raw, 0); end >= 0 {
		raw = raw[:end]
	}
	return string(raw)
}
