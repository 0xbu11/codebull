//go:build !go1.23

package function

import (
	"fmt"
	"runtime"

	"github.com/0xbu11/codebull/pkg/variable"
	"golang.org/x/arch/x86/x86asm"
)

func AnalyzePrologue(reader *variable.BinaryReader, entry uint64) ([]byte, uint64, error) {
	buf, err := reader.ReadInstructions(entry, 64)
	if err != nil {
		return nil, 0, err
	}

	mode := 64
	if runtime.GOARCH == "386" {
		mode = 32
	}

	offset := 0
	prologueEnd := 0
	seenAlloc := false
	var morestackAddr uint64

	for offset < len(buf) {
		instPC := entry + uint64(offset)
		inst, err := x86asm.Decode(buf[offset:], mode)
		if err != nil {
			break
		}

		size := inst.Len

		if (inst.Op == x86asm.JBE || inst.Op == x86asm.JB) && morestackAddr == 0 {
			if rel, ok := inst.Args[0].(x86asm.Rel); ok {
				target := int64(instPC) + int64(size) + int64(rel)
				msAddr, err := findMorestackAddr(reader, uint64(target), mode)
				if err == nil {
					morestackAddr = msAddr
				}
			}
		}

		if inst.Op == x86asm.SUB && (inst.Args[0] == x86asm.RSP || inst.Args[0] == x86asm.ESP) {
			seenAlloc = true
		}

		offset += size
		prologueEnd = offset

		if seenAlloc {
			if offset < len(buf) {
				nextInst, _ := x86asm.Decode(buf[offset:], mode)
				if nextInst.Op == x86asm.MOV && isSavingBP(nextInst) {
					offset += nextInst.Len
					prologueEnd = offset
					if offset < len(buf) {
						nextNext, _ := x86asm.Decode(buf[offset:], mode)
						if nextNext.Op == x86asm.LEA && isSettingBP(nextNext) {
							offset += nextNext.Len
							prologueEnd = offset
						}
					}
				}
			}
			break
		}
	}

	if prologueEnd > len(buf) {
		prologueEnd = len(buf)
	}
	return buf[:prologueEnd], morestackAddr, nil
}

func findMorestackAddr(reader *variable.BinaryReader, target uint64, mode int) (uint64, error) {
	buf, err := reader.ReadInstructions(target, 32)
	if err != nil {
		return 0, err
	}

	offset := 0
	for offset < len(buf) {
		instPC := target + uint64(offset)
		inst, err := x86asm.Decode(buf[offset:], mode)
		if err != nil {
			break
		}

		if inst.Op == x86asm.CALL {
			if rel, ok := inst.Args[0].(x86asm.Rel); ok {
				dest := int64(instPC) + int64(inst.Len) + int64(rel)
				return uint64(dest), nil
			}
		}

		offset += inst.Len
	}
	return 0, fmt.Errorf("morestack call not found in cold path")
}

func isSavingBP(inst x86asm.Inst) bool {
	if len(inst.Args) != 2 {
		return false
	}

	mem, ok := inst.Args[0].(x86asm.Mem)
	if !ok {
		return false
	}
	if mem.Base != x86asm.RSP {
		return false
	}

	reg, ok := inst.Args[1].(x86asm.Reg)
	if !ok {
		return false
	}
	if reg != x86asm.RBP {
		return false
	}

	return true
}

func isSettingBP(inst x86asm.Inst) bool {
	if len(inst.Args) != 2 {
		return false
	}
	reg, ok := inst.Args[0].(x86asm.Reg)
	if !ok || reg != x86asm.RBP {
		return false
	}
	mem, ok := inst.Args[1].(x86asm.Mem)
	if !ok || mem.Base != x86asm.RSP {
		return false
	}
	return true
}
