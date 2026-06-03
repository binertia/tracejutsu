//go:build linux && amd64

package ebpf

import (
	"encoding/binary"
	"io"
	"testing"

	"github.com/cilium/ebpf"
)

func TestProgramSpecsMarshal(t *testing.T) {
	specs := map[string]*ebpf.ProgramSpec{
		"execve":           execveProgramSpec(1, 2),
		"connect_enter":    connectEnterProgramSpec(3, 4),
		"connect_exit":     connectExitProgramSpec(1, 2, 3),
		"file_write_enter": fileWriteEnterProgramSpec(3, 4, 0),
		"file_write_skip":  fileWriteEnterProgramSpec(3, 4, 1234),
		"file_write_exit":  fileWriteExitProgramSpec(1, 2, 3, 0),
		"file_write_floor": fileWriteExitProgramSpec(1, 2, 3, 4096),
		"chmod_enter":      chmodEnterProgramSpec(3, 4),
		"chmod_exit":       chmodExitProgramSpec(1, 2, 3),
	}
	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			if err := spec.Instructions.Marshal(io.Discard, binary.LittleEndian); err != nil {
				t.Fatal(err)
			}
		})
	}
}
