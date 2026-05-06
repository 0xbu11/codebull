//go:build !go1.27

package module

import "unsafe"

//go:linkname lastmoduledatap runtime.lastmoduledatap
var lastmoduledatap *moduledata

var registeredModules []*moduledata

func GetModules() []*moduledata {
	if len(registeredModules) == 0 {
		return nil
	}
	out := make([]*moduledata, len(registeredModules))
	copy(out, registeredModules)
	return out
}

//go:linkname findfunc runtime.findfunc
func findfunc(pc uintptr) funcInfo

const pcQuantumRuntime = 1

func step(p []byte, pc *uintptr, val *int32, first bool) (newp []byte, ok bool) {
	if len(p) == 0 {
		return nil, false
	}
	uvdelta := uint32(p[0])
	if uvdelta == 0 && !first {
		return nil, false
	}
	n := uint32(1)
	if uvdelta&0x80 != 0 {
		var ok bool
		n, uvdelta, ok = readvarint(p)
		if !ok {
			return nil, false
		}
	}
	*val += int32(-(uvdelta & 1) ^ (uvdelta >> 1))
	p = p[n:]
	if len(p) == 0 {
		return nil, false
	}

	pcdelta := uint32(p[0])
	n = 1
	if pcdelta&0x80 != 0 {
		var ok bool
		n, pcdelta, ok = readvarint(p)
		if !ok {
			return nil, false
		}
	}
	p = p[n:]
	*pc += uintptr(pcdelta * pcQuantumRuntime)
	return p, true
}

func readvarint(p []byte) (read uint32, val uint32, ok bool) {
	var v, shift, n uint32
	for {
		if int(n) >= len(p) {
			return 0, 0, false
		}
		b := p[n]
		n++
		v |= uint32(b&0x7F) << (shift & 31)
		if b&0x80 == 0 {
			return n, v, true
		}
		shift += 7
	}
}

func pcdatavalue1(f funcInfo, table uint32, targetpc uintptr, strict bool) int32 {
	if table >= f.npcdata {
		return -1
	}
	off := pcdatastart(f, table)
	v, _ := pcvalue(f, off, targetpc, strict)
	return v
}

func pcdatastart(f funcInfo, table uint32) uint32 {
	ptr := uintptr(unsafe.Pointer(f._func)) + unsafe.Sizeof(_func{}) + uintptr(table)*4
	return *(*uint32)(unsafe.Pointer(ptr))
}

func funcdata(f funcInfo, i uint8) unsafe.Pointer {
	if i >= f.nfuncdata {
		return nil
	}
	base := f.datap.gofunc
	ptr := uintptr(unsafe.Pointer(f._func)) + unsafe.Sizeof(_func{}) + uintptr(f.npcdata)*4 + uintptr(i)*4
	off := *(*uint32)(unsafe.Pointer(ptr))
	if off == ^uint32(0) {
		return nil
	}
	return unsafe.Pointer(base + uintptr(off))
}

func pcvalue(f funcInfo, off uint32, targetpc uintptr, strict bool) (int32, uintptr) {
	_ = strict
	if off == 0 || !f.valid() || f.datap == nil {
		return -1, 0
	}
	if off >= uint32(len(f.datap.pctab)) {
		return -1, 0
	}

	p := f.datap.pctab[off:]
	pc := uintptr(f.Entry())
	prevpc := pc
	val := int32(-1)
	for {
		var ok bool
		p, ok = step(p, &pc, &val, pc == uintptr(f.Entry()))
		if !ok || targetpc < pc {
			return val, prevpc
		}
		prevpc = pc
	}
}

func funcname(f funcInfo) string {
	if !f.valid() || f.datap == nil {
		return ""
	}
	if f.nameOff <= 0 || int(f.nameOff) >= len(f.datap.funcnametab) {
		return ""
	}
	return readCString(f.datap.funcnametab[f.nameOff:])
}

func funcline1(f funcInfo, targetpc uintptr, strict bool) (file string, line int32) {
	if !f.valid() || f.datap == nil {
		return "?", 0
	}
	fileno, _ := pcvalue(f, f.pcfile, targetpc, strict)
	line, _ = pcvalue(f, f.pcln, targetpc, strict)
	if fileno == -1 || line == -1 {
		return "?", 0
	}
	return funcfile(f, fileno), line
}

func funcfile(f funcInfo, fileno int32) string {
	if !f.valid() || f.datap == nil {
		return "?"
	}
	idx := int(f.cuOffset) + int(fileno)
	if idx < 0 || idx >= len(f.datap.cutab) {
		return "?"
	}
	fileoff := f.datap.cutab[idx]
	if fileoff == ^uint32(0) || int(fileoff) >= len(f.datap.filetab) {
		return "?"
	}
	return readCString(f.datap.filetab[fileoff:])
}

func readCString(buf []byte) string {
	for i, b := range buf {
		if b == 0 {
			return string(buf[:i])
		}
	}
	return string(buf)
}

func FindFunc(pc uint64) *funcInfo {
	f := findfunc(uintptr(pc))
	if f.valid() {
		return &f
	}
	return nil
}

func (f funcInfo) valid() bool {
	return f._func != nil
}

func (f *funcInfo) Entry() uint64 {
	return uint64(f.entryOff) + uint64(f.datap.text) // entryOff is relative to text? Wait, let's verify symtab.go
}
