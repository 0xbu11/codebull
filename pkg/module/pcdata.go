//go:build !go1.27

package module

import "github.com/0xbu11/codebull/pkg/debugflag"

type PCDataEntry struct {
	Offset uintptr
	Value  int32
}

const pcQuantum = 1 // Min instruction size, usually 1 for x86/amd64

func decodePCDataEntries(table int, p []byte) (pcDataEntries []PCDataEntry) {
	if p == nil {
		return pcDataEntries
	}
	var pc uintptr
	val := int32(-1)
	var ok bool
	p, ok = step(p, &pc, &val, true)
	for {
		if !ok {
			return pcDataEntries
		}
		debugflag.Printf("DECODE: Table: %d PC: %d Val: %d", table, pc, val)
		pcDataEntries = append(pcDataEntries, PCDataEntry{Offset: pc, Value: val})
		if len(p) <= 0 {
			return pcDataEntries
		}
		p, ok = step(p, &pc, &val, false)
	}
}

func encodePCDataEntries(pcDataEntries []PCDataEntry) (encoded []byte, err error) {
	if len(pcDataEntries) == 0 {
		return []byte{0}, nil
	}
	encoded = make([]byte, 0, len(pcDataEntries)*4)
	prevOffset := int32(0)
	prevValue := int32(-1)

	for i := 0; i < len(pcDataEntries); i++ {
		for i+1 < len(pcDataEntries) && pcDataEntries[i+1].Offset == pcDataEntries[i].Offset {
			i++
		}


		newPair := pcDataEntries[i]



		valueDelta := newPair.Value - prevValue
		offsetDelta := int32(newPair.Offset) - prevOffset
		encoded, err = writePCDataEntry(encoded, valueDelta, offsetDelta)
		if err != nil {
			return nil, err
		}
		prevOffset = int32(newPair.Offset)
		prevValue = newPair.Value
	}

	encoded = append(encoded, 0)

	return encoded, nil
}

func writePCDataEntry(p []byte, value int32, offset int32) ([]byte, error) {
	v := encode(value)
	if v == 0 {
		p = append(p, 0x80, 0x00)
	} else {
		p = writeUvarint(p, uint64(v))
	}
	p = writeUvarint(p, uint64(offset/pcQuantum))
	return p, nil
}

func encode(v int32) uint32 {
	return uint32(v<<1) ^ uint32(v>>31)
}

func writeUvarint(buf []byte, x uint64) []byte {
	for x >= 0x80 {
		buf = append(buf, byte(x)|0x80)
		x >>= 7
	}
	buf = append(buf, byte(x))
	return buf
}
