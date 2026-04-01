//go:build !go1.23

package variable

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/0xbu11/codebull/pkg/debugflag"
)

const (
	DW_OP_addr           = 0x03
	DW_OP_reg0           = 0x50
	DW_OP_reg31          = 0x6f
	DW_OP_breg0          = 0x70
	DW_OP_breg31         = 0x8f
	DW_OP_regx           = 0x90
	DW_OP_fbreg          = 0x91
	DW_OP_bregx          = 0x92
	DW_OP_call_frame_cfa = 0x9c
)

func (v *Variable) GetRegsUsed() ([]uint64, error) {
	if len(v.Location) == 0 {
		return nil, nil
	}

	var regs []uint64
	buf := bytes.NewBuffer(v.Location)

	for buf.Len() > 0 {
		opcode, err := buf.ReadByte()
		if err != nil {
			return nil, err
		}

		switch {
		case opcode >= DW_OP_reg0 && opcode <= DW_OP_reg31:
			regs = append(regs, uint64(opcode-DW_OP_reg0))

		case opcode >= DW_OP_breg0 && opcode <= DW_OP_breg31:
			regs = append(regs, uint64(opcode-DW_OP_breg0))
			if _, err := readSLEB128(buf); err != nil {
				return nil, err
			}

		case opcode == DW_OP_regx:
			reg, err := readULEB128(buf)
			if err != nil {
				return nil, err
			}
			regs = append(regs, reg)

		case opcode == DW_OP_bregx:
			reg, err := readULEB128(buf)
			if err != nil {
				return nil, err
			}
			regs = append(regs, reg)
			if _, err := readSLEB128(buf); err != nil {
				return nil, err
			}

		case opcode == DW_OP_fbreg:
			if _, err := readSLEB128(buf); err != nil {
				return nil, err
			}

		case opcode == DW_OP_addr:
			if buf.Len() < 8 {
				return nil, fmt.Errorf("insufficient data for DW_OP_addr")
			}
			buf.Next(8)

		case opcode == DW_OP_call_frame_cfa:

		default:
		}
	}

	return regs, nil
}

func readULEB128(b *bytes.Buffer) (uint64, error) {
	var result uint64
	var shift uint
	for {
		byteVal, err := b.ReadByte()
		if err != nil {
			return 0, err
		}
		result |= uint64(byteVal&0x7f) << shift
		shift += 7
		if byteVal&0x80 == 0 {
			break
		}
	}
	return result, nil
}

func decodeSimpleLocation(loc []byte) (string, error) {
	if len(loc) == 0 {
		return "empty", nil
	}

	buf := bytes.NewBuffer(loc)
	opcode, _ := buf.ReadByte()

	switch opcode {
	case DW_OP_addr:
		var addr uint64
		if err := binary.Read(buf, binary.LittleEndian, &addr); err != nil {
			return "", err
		}
		return fmt.Sprintf("Addr: 0x%x", addr), nil
	case DW_OP_fbreg:
		offset, _ := readSLEB128(buf)
		return fmt.Sprintf("FBReg + %d", offset), nil
	case DW_OP_call_frame_cfa:
		return "CallFrameCFA", nil
	default:
		return fmt.Sprintf("Opcode: 0x%x len=%d", opcode, len(loc)), nil
	}
}

func readSLEB128(b *bytes.Buffer) (int64, error) {
	var result int64
	var shift uint
	for {
		byteVal, err := b.ReadByte()
		if err != nil {
			return 0, err
		}
		result |= int64(byteVal&0x7f) << shift
		shift += 7
		if byteVal&0x80 == 0 {
			if (byteVal & 0x40) != 0 {
				result |= (^int64(0)) << shift
			}
			break
		}
	}
	return result, nil
}

type Regs interface {
	Get(dwarfReg uint64) (uint64, error)
}


func (v *Variable) Evaluate(regs Regs, frameBase uint64, currPC uint64) (uint64, error) {
	var locExpr []byte

	if len(v.LocList) > 0 {
		found := false
		for _, entry := range v.LocList {
			if currPC >= entry.LowPC && currPC < entry.HighPC {
				locExpr = entry.Loc
				found = true
				break
			}
		}
		if !found {
			return 0, fmt.Errorf("no location for PC 0x%x", currPC)
		}
	} else {
		locExpr = v.Location
	}

	if len(locExpr) == 0 {
		return 0, fmt.Errorf("empty location")
	}

	debugflag.Printf("DEBUG EVAL: Evaluate Variable %s PC=0x%x frameBase=0x%x MatchedLocExpr=(%x)", v.Name, currPC, frameBase, locExpr)

	buf := bytes.NewBuffer(locExpr)
	var stack []uint64

	for buf.Len() > 0 {
		opcode, err := buf.ReadByte()
		if err != nil {
			return 0, err
		}

		switch {
		case opcode == DW_OP_addr:
			var addr uint64
			if err := binary.Read(buf, binary.LittleEndian, &addr); err != nil {
				return 0, err
			}
			stack = append(stack, addr)

		case opcode == DW_OP_fbreg:
			offset, err := readSLEB128(buf)
			if err != nil {
				return 0, err
			}
			addr := uint64(int64(frameBase) + offset)
			stack = append(stack, addr)

		case opcode == DW_OP_call_frame_cfa:
			stack = append(stack, frameBase)

		case opcode >= DW_OP_reg0 && opcode <= DW_OP_reg31:
			regNum := uint64(opcode - DW_OP_reg0)
			val, err := regs.Get(regNum)
			if err != nil {
				return 0, err
			}
			stack = append(stack, val)
			if len(locExpr) == 1 {
				v.IsRegister = true
			}

		case opcode >= DW_OP_breg0 && opcode <= DW_OP_breg31:
			regNum := uint64(opcode - DW_OP_breg0)
			offset, err := readSLEB128(buf)
			if err != nil {
				return 0, err
			}
			regVal, err := regs.Get(regNum)
			if err != nil {
				return 0, err
			}
			stack = append(stack, uint64(int64(regVal)+offset))

		case opcode == DW_OP_regx:
			regNum, err := readULEB128(buf)
			if err != nil {
				return 0, err
			}
			val, err := regs.Get(regNum)
			if err != nil {
				return 0, err
			}
			stack = append(stack, val)
			if buf.Len() == 0 && len(stack) == 1 {
				v.IsRegister = true
			}

		case opcode == DW_OP_bregx:
			regNum, err := readULEB128(buf)
			if err != nil {
				return 0, err
			}
			offset, err := readSLEB128(buf)
			if err != nil {
				return 0, err
			}
			regVal, err := regs.Get(regNum)
			if err != nil {
				return 0, err
			}
			stack = append(stack, uint64(int64(regVal)+offset))

		default:
			return 0, fmt.Errorf("unsupported opcode in Evaluate: 0x%x", opcode)
		}
	}

	if len(stack) == 0 {
		return 0, fmt.Errorf("stack empty after evaluation")
	}
	return stack[len(stack)-1], nil
}
