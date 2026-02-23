//go:build !go1.23

package function

import (
	"encoding/binary"

	"golang.org/x/arch/x86/x86asm"
)

type Assembler struct {
	buf []byte
}

func NewAssembler() *Assembler {
	return &Assembler{
		buf: make([]byte, 0, 64),
	}
}

func (a *Assembler) Bytes() []byte {
	return a.buf
}

func (a *Assembler) MovReqImm(reg x86asm.Reg, imm uint64) {


	rex := byte(0x48) // REX.W
	if reg >= x86asm.R8 && reg <= x86asm.R15 {
		rex |= 0x01 // REX.B
	}

	baseOp := byte(0xB8)
	rd := byte(reg & 7) // Lower 3 bits

	a.buf = append(a.buf, rex, baseOp|rd)
	var immBytes [8]byte
	binary.LittleEndian.PutUint64(immBytes[:], imm)
	a.buf = append(a.buf, immBytes[:]...)
}

func (a *Assembler) JmpReg(reg x86asm.Reg) {

	rex := byte(0x00)
	if reg >= x86asm.R8 && reg <= x86asm.R15 {
		rex |= 0x41 // REX.B, and maybe padding? Usually just REX.B is enough for extended reg.
	}

	if rex != 0 {
		a.buf = append(a.buf, rex)
	}
	a.buf = append(a.buf, 0xFF)

	mod := byte(3)   // 11
	regOp := byte(4) // 100
	rm := byte(reg & 7)

	modRM := (mod << 6) | (regOp << 3) | rm
	a.buf = append(a.buf, modRM)
}

func (a *Assembler) MovRegMem(dst x86asm.Reg, base x86asm.Reg, disp int32) {

	rex := byte(0x48) // REX.W
	if dst >= x86asm.R8 && dst <= x86asm.R15 {
		rex |= 0x04 // REX.R
	}
	if base >= x86asm.R8 && base <= x86asm.R15 {
		rex |= 0x01 // REX.B
	}

	a.buf = append(a.buf, rex, 0x8B)


	mod := byte(2)
	regOp := byte(dst & 7)
	rm := byte(base & 7)

	if (base & 7) == 4 { // RSP or R12
		modRM := (mod << 6) | (regOp << 3) | 4 // RM=4 indicates SIB
		a.buf = append(a.buf, modRM)

		sib := byte(0x20) | byte(base&7) // 00 100 100 -> Scale 0, Index 4 (SP/none), Base 4 (R12/SP)
		a.buf = append(a.buf, sib)
	} else {
		modRM := (mod << 6) | (regOp << 3) | rm
		a.buf = append(a.buf, modRM)
	}

	var dispBytes [4]byte
	binary.LittleEndian.PutUint32(dispBytes[:], uint32(disp))
	a.buf = append(a.buf, dispBytes[:]...)
}

func (a *Assembler) CallReg(reg x86asm.Reg) {
	rex := byte(0x00)
	if reg >= x86asm.R8 && reg <= x86asm.R15 {
		rex |= 0x41 // REX.B
	}

	if rex != 0 {
		a.buf = append(a.buf, rex)
	}
	a.buf = append(a.buf, 0xFF)

	mod := byte(3)   // 11
	regOp := byte(2) // 010 (2)
	rm := byte(reg & 7)

	modRM := (mod << 6) | (regOp << 3) | rm
	a.buf = append(a.buf, modRM)
}

func (a *Assembler) CmpRegReg(r1 x86asm.Reg, r2 x86asm.Reg) {

	rex := byte(0x48)
	if r1 >= x86asm.R8 && r1 <= x86asm.R15 {
		rex |= 0x04 // REX.R (r1 is reg)
	}
	if r2 >= x86asm.R8 && r2 <= x86asm.R15 {
		rex |= 0x01 // REX.B (r2 is rm)
	}

	a.buf = append(a.buf, rex, 0x39) // 39 /r : CMP r/m64, r64. MR encoding.




	mod := byte(3)
	regOp := byte(r1 & 7)
	rm := byte(r2 & 7)

	rex = 0x48
	if r1 >= x86asm.R8 && r1 <= x86asm.R15 {
		rex |= 0x04 // REX.R
	}
	if r2 >= x86asm.R8 && r2 <= x86asm.R15 {
		rex |= 0x01 // REX.B
	}

	a.buf = append(a.buf, rex, 0x3B)
	modRM := (mod << 6) | (regOp << 3) | rm
	a.buf = append(a.buf, modRM)
}

func (a *Assembler) Lea(dst x86asm.Reg, base x86asm.Reg, disp int32) {
	rex := byte(0x48)
	if dst >= x86asm.R8 && dst <= x86asm.R15 {
		rex |= 0x04 // REX.R
	}
	if base >= x86asm.R8 && base <= x86asm.R15 {
		rex |= 0x01 // REX.B
	}

	a.buf = append(a.buf, rex, 0x8D)

	mod := byte(2) // disp32
	regOp := byte(dst & 7)
	rm := byte(base & 7)

	if (base & 7) == 4 { // RSP or R12
		modRM := (mod << 6) | (regOp << 3) | 4
		a.buf = append(a.buf, modRM)
		sib := byte(0x20) | byte(base&7)
		a.buf = append(a.buf, sib)
	} else {
		modRM := (mod << 6) | (regOp << 3) | rm
		a.buf = append(a.buf, modRM)
	}

	var dispBytes [4]byte
	binary.LittleEndian.PutUint32(dispBytes[:], uint32(disp))
	a.buf = append(a.buf, dispBytes[:]...)
}

func (a *Assembler) JhiRel32(rel int32) {
	a.buf = append(a.buf, 0x0F, 0x87)
	var relBytes [4]byte
	binary.LittleEndian.PutUint32(relBytes[:], uint32(rel))
	a.buf = append(a.buf, relBytes[:]...)
}

func (a *Assembler) JmpRel32(rel int32) {
	a.buf = append(a.buf, 0xE9)
	var relBytes [4]byte
	binary.LittleEndian.PutUint32(relBytes[:], uint32(rel))
	a.buf = append(a.buf, relBytes[:]...)
}
