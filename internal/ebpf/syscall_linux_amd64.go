//go:build linux && amd64

package ebpf

import (
	"os"
	"path/filepath"
	"strconv"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

const (
	ptRegsDXOffset     = 96
	maxPendingSyscalls = 16384
)

func newPendingSyscallMap(name string, valueSize int) (*cebpf.Map, error) {
	return cebpf.NewMap(&cebpf.MapSpec{
		Type:       cebpf.Hash,
		Name:       name,
		KeySize:    8,
		ValueSize:  uint32(valueSize),
		MaxEntries: maxPendingSyscalls,
	})
}

func storePendingSyscall(mapFD int, keyOffset, recordStart int16) asm.Instructions {
	return asm.Instructions{
		asm.LoadMapPtr(asm.R1, mapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(keyOffset)),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, int32(recordStart)),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
	}
}

func completedSyscallProgramSpec(name string, ringBufferFD, dropCounterFD, pendingFD int, recordSize, completionTimestampOffset, returnValueOffset int16) *cebpf.ProgramSpec {
	return completedSyscallProgramSpecWithExitFilter(
		name,
		ringBufferFD,
		dropCounterFD,
		pendingFD,
		recordSize,
		completionTimestampOffset,
		returnValueOffset,
		nil,
	)
}

func completedSyscallProgramSpecWithExitFilter(name string, ringBufferFD, dropCounterFD, pendingFD int, recordSize, completionTimestampOffset, returnValueOffset int16, beforeOutput asm.Instructions) *cebpf.ProgramSpec {
	recordStart := -recordSize
	keyOffset := recordStart - 8
	tempValue := keyOffset - 8

	instructions := asm.Instructions{
		asm.Mov.Reg(asm.R6, asm.R1),
		asm.LoadMem(asm.R8, asm.R6, 8, asm.DWord),

		asm.FnGetCurrentPidTgid.Call(),
		asm.StoreMem(asm.RFP, keyOffset, asm.R0, asm.DWord),

		asm.LoadMapPtr(asm.R1, pendingFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(keyOffset)),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "exit"),
	}
	for offset := int16(0); offset < recordSize; offset += 8 {
		instructions = append(instructions,
			asm.LoadMem(asm.R7, asm.R0, offset, asm.DWord),
			asm.StoreMem(asm.RFP, recordStart+offset, asm.R7, asm.DWord),
		)
	}
	instructions = append(instructions,
		asm.StoreMem(asm.RFP, recordStart+returnValueOffset, asm.R8, asm.DWord),
		asm.FnKtimeGetNs.Call(),
		asm.StoreMem(asm.RFP, recordStart+completionTimestampOffset, asm.R0, asm.DWord),

		asm.LoadMapPtr(asm.R1, pendingFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(keyOffset)),
		asm.FnMapDeleteElem.Call(),
	)
	instructions = append(instructions, beforeOutput...)
	instructions = append(instructions,
		asm.LoadMapPtr(asm.R1, ringBufferFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(recordStart)),
		asm.Mov.Imm(asm.R3, int32(recordSize)),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
	)
	instructions = append(instructions, countRingBufferDrop(dropCounterFD, tempValue)...)
	instructions = append(instructions,
		asm.Mov.Imm(asm.R0, 0).WithSymbol("exit"),
		asm.Return(),
	)

	return &cebpf.ProgramSpec{
		Name:         name,
		Type:         cebpf.RawTracepoint,
		License:      "GPL",
		Instructions: instructions,
	}
}

func syscallOutcome(returnValue int64) string {
	if returnValue < 0 {
		return "failed"
	}
	return "success"
}

func syscallErrno(returnValue int64) int64 {
	if returnValue < 0 {
		return -returnValue
	}
	return 0
}

func readRegisterArgument(ctx asm.Register, registerOffset int32, frame asm.Register, tempOffset, destinationOffset int16, size asm.Size) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R3, ctx, 0, asm.DWord),
		asm.Add.Imm(asm.R3, registerOffset),
		asm.Mov.Reg(asm.R1, frame),
		asm.Add.Imm(asm.R1, int32(tempOffset)),
		asm.Mov.Imm(asm.R2, 8),
		asm.FnProbeReadKernel.Call(),
		asm.LoadMem(asm.R7, frame, tempOffset, asm.DWord),
		asm.StoreMem(frame, destinationOffset, asm.R7, size),
	}
}

func readPathArgument(ctx asm.Register, registerOffset int32, frame asm.Register, tempOffset, destinationOffset int16) asm.Instructions {
	return asm.Instructions{
		asm.LoadMem(asm.R3, ctx, 0, asm.DWord),
		asm.Add.Imm(asm.R3, registerOffset),
		asm.Mov.Reg(asm.R1, frame),
		asm.Add.Imm(asm.R1, int32(tempOffset)),
		asm.Mov.Imm(asm.R2, 8),
		asm.FnProbeReadKernel.Call(),
		asm.LoadMem(asm.R3, frame, tempOffset, asm.DWord),
		asm.Mov.Reg(asm.R1, frame),
		asm.Add.Imm(asm.R1, int32(destinationOffset)),
		asm.Mov.Imm(asm.R2, filenameSize),
		asm.FnProbeReadUserStr.Call(),
	}
}

func readProcFD(procRoot string, pid, fd int) string {
	if pid <= 0 || fd < 0 {
		return ""
	}
	path, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "fd", strconv.Itoa(fd)))
	if err != nil || !filepath.IsAbs(path) {
		return ""
	}
	return filepath.Clean(path)
}

func resolveProcPath(procRoot string, pid, dirfd int, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}

	base := readProcCWD(procRoot, pid)
	if dirfd != atFDCWD {
		base = readProcFD(procRoot, pid, dirfd)
	}
	if base == "" || !filepath.IsAbs(base) {
		return ""
	}
	return filepath.Clean(filepath.Join(base, path))
}
