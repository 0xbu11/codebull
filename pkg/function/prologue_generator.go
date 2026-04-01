//go:build !go1.23

package function

import (
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/arch/x86/x86asm"
)

type Instruction struct {
	PC    uintptr
	Inst  x86asm.Inst
	Bytes []byte
}

type PrologueGenerator struct {
	stackUsage           int // 0x28 + 256 + ...
	fallbackAddr         uint64
	morestackAddr        uint64
	goPrologueExists     bool
	epilogueInstructions []Instruction
	regsUsed             []x86asm.Reg
}

const (
	stackGuardOffset = 0x10 // standard for amd64
	stackUsageBuffer = 0x28 + 256
)

func NewPrologueGenerator(funcEntry uintptr, funcEnd uintptr, stackUsage int, fallbackAddr uint64, regsUsed []x86asm.Reg) (*PrologueGenerator, error) {
	instructions, err := decodeInstructions(funcEntry, funcEnd)
	if err != nil {
		return nil, err
	}

	g := &PrologueGenerator{
		stackUsage:   stackUsage,
		fallbackAddr: fallbackAddr,
		regsUsed:     regsUsed,
	}

	g.epilogueInstructions, g.morestackAddr, g.goPrologueExists = getOriginalEpilogue(instructions)
	return g, nil
}

func DwarfRegToX86asm(reg uint64) (x86asm.Reg, bool) {

	switch reg {
	case 0:
		return x86asm.RAX, true
	case 1:
		return x86asm.RDX, true
	case 2:
		return x86asm.RCX, true
	case 3:
		return x86asm.RBX, true
	case 4:
		return x86asm.RSI, true
	case 5:
		return x86asm.RDI, true
	case 6:
		return x86asm.RBP, true
	case 7:
		return x86asm.RSP, true
	case 8:
		return x86asm.R8, true
	case 9:
		return x86asm.R9, true
	case 10:
		return x86asm.R10, true
	case 11:
		return x86asm.R11, true
	case 12:
		return x86asm.R12, true
	case 13:
		return x86asm.R13, true
	case 14:
		return x86asm.R14, true
	case 15:
		return x86asm.R15, true
	case 16:
		return x86asm.RIP, true
	}
	return 0, false
}

func (g *PrologueGenerator) GenerateLongPrologue() ([]byte, error) {
	asm := NewAssembler()


	/*
		Original Go prologue:
		MOVQ	(TLS), R14
		CMPQ	RSP, 0x10(R14)
		JLS	call_morestack

		Hooker prologue (from reference):
		MOVQ 	R12, (TLS/R14?) -> Go uses R14 for current G usually, but in ABI0 it might be different.
		Wait, the reference code had:
		common.MovGToR12(b) => MOVQ R12, QWORD PTR FS:0xfffffff8 (Get G to R12)
		b.Inst(assembler.AMOVQ, x86asm.R12, assembler.Mem{Base: x86asm.R12, Disp: common.StackguardOffset}), => MOVQ R12, [R12+0x10] (Load stackguard to R12)
		b.Inst(assembler.ALEAQ, x86asm.R13, assembler.Mem{Base: x86asm.RSP, Disp: -int64(g.stackUsage + stackUsageBuffer)}), => LEA R13, [RSP - size]
		b.Cmp(x86asm.R13, x86asm.R12)
		b.BranchToLabel(assembler.AJHI, endLabel) => If R13 > R12 (Stack ptr > Guard), then safe, Jump to End.

		Fallback:
		MOVQ R13, Imm(morestackAddr)
		CALL R13
		JMP Start
	*/



	asm.buf = append(asm.buf, 0x64, 0x4C, 0x8B, 0x24, 0x25, 0xF8, 0xFF, 0xFF, 0xFF)

	asm.MovRegMem(x86asm.R12, x86asm.R12, stackGuardOffset)

	neededStack := -(g.stackUsage + stackUsageBuffer)
	asm.Lea(x86asm.R13, x86asm.RSP, int32(neededStack))

	asm.CmpRegReg(x86asm.R13, x86asm.R12)

	jhiIdx := len(asm.buf)
	asm.JhiRel32(0)

	asm.MovReqImm(x86asm.R13, g.morestackAddr)
	asm.CallReg(x86asm.R13)


	jmpBackLen := 5
	relBack := 0 - (len(asm.buf) + jmpBackLen)
	asm.JmpRel32(int32(relBack))

	endLabelOffset := len(asm.buf)

	relJhi := int32(endLabelOffset - (jhiIdx + 6))
	binary.LittleEndian.PutUint32(asm.buf[jhiIdx+2:], uint32(relJhi))

	asm.MovReqImm(x86asm.R13, g.fallbackAddr)
	asm.JmpReg(x86asm.R13)

	return asm.Bytes(), nil
}

func decodeInstructions(start, end uintptr) ([]Instruction, error) {
	if end <= start {
		return nil, fmt.Errorf("invalid function range: %x - %x", start, end)
	}
	size := int(end - start)

	if size > 100000 {
		return nil, fmt.Errorf("function too large: %d bytes", size)
	}


	ptr := unsafe.Pointer(start)
	data := (*[1 << 30]byte)(ptr)[:size:size]

	var insts []Instruction
	offset := 0
	for offset < size {
		inst, err := x86asm.Decode(data[offset:], 64)
		if err != nil {
			break
		}
		instByts := make([]byte, inst.Len)
		copy(instByts, data[offset:offset+inst.Len])

		insts = append(insts, Instruction{
			PC:    start + uintptr(offset),
			Inst:  inst,
			Bytes: instByts,
		})
		offset += inst.Len
	}
	return insts, nil
}


func getOriginalEpilogue(instructions []Instruction) ([]Instruction, uint64, bool) {
	_, epilogueStart, ok := findFirstJmp(instructions, 0)
	if !ok {
		return nil, 0, false
	}

	morestackCallIndex, morestackAddr, ok := findMorestackCall(instructions, epilogueStart)
	if !ok {
		return nil, 0, false
	}

	epilogueEnd, ok := findJmpToStart(instructions, morestackCallIndex)
	if !ok {
		return nil, 0, false
	}


	return instructions[epilogueStart:epilogueEnd], uint64(morestackAddr), true
}

func findFirstJmp(instructions []Instruction, startIndex int) (jmpIndex int, jmpDestIndex int, ok bool) {
	for i := startIndex; i < len(instructions); i++ {
		inst := instructions[i].Inst

		switch inst.Op {
		case x86asm.JMP, x86asm.JNE, x86asm.JE, x86asm.JLE, x86asm.JGE, x86asm.JL, x86asm.JG, x86asm.JBE, x86asm.JB, x86asm.JAE, x86asm.JA:
			if len(inst.Args) > 0 {
				if rel, isRel := inst.Args[0].(x86asm.Rel); isRel {
					jmpIndex = i
					targetPC := int64(instructions[i].PC) + int64(inst.Len) + int64(rel)

					destFound := false
					for j, targetInst := range instructions {
						if int64(targetInst.PC) == targetPC {
							jmpDestIndex = j
							destFound = true
							break
						}
					}

					if destFound {
						if jmpDestIndex == jmpIndex+1 {
							continue
						}
						return jmpIndex, jmpDestIndex, true
					}
				}
			}
		}
	}
	return 0, 0, false
}

func findMorestackCall(instructions []Instruction, startIndex int) (callIndex int, callDest uintptr, ok bool) {
	for i := startIndex; i < len(instructions); i++ {
		inst := instructions[i].Inst
		if inst.Op == x86asm.CALL && len(inst.Args) > 0 {
			if rel, isRel := inst.Args[0].(x86asm.Rel); isRel {
				callIndex = i
				targetPC := int64(instructions[i].PC) + int64(inst.Len) + int64(rel)
				callDest = uintptr(targetPC)
				return callIndex, callDest, true
			}
		}
	}
	return 0, 0, false
}

func findJmpToStart(instructions []Instruction, startIndex int) (jmpIndex int, ok bool) {
	jmpi, desti, found := findFirstJmp(instructions, startIndex)
	if found && desti == 0 {
		return jmpi, true
	}
	return 0, false
}
