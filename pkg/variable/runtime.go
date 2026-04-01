//go:build !go1.23

package variable

import (
	"unsafe"
)

//go:linkname FindFunc runtime.findfunc
func FindFunc(_ uintptr) FuncInfo



func step(p []byte, pc *uintptr, val *int32, first bool) (newp []byte, ok bool) {
	p, uvdelta := readvarint(p)
	if uvdelta == 0 && !first {
		return nil, false
	}
	if uvdelta&1 != 0 {
		uvdelta = ^(uvdelta >> 1)
	} else {
		uvdelta >>= 1
	}
	vdelta := int32(uvdelta)

	p, pcdelta := readvarint(p)

	*pc += uintptr(pcdelta * 1) // pcQuantum=1 for amd64
	*val += vdelta

	return p, true
}

func readvarint(p []byte) ([]byte, uint32) {
	var v uint32
	var shift uint
	for i, b := range p {
		v |= uint32(b&0x7F) << shift
		if b&0x80 == 0 {
			return p[i+1:], v
		}
		shift += 7
	}
	return nil, 0
}

type FuncInfo struct {
	*_func
	datap *moduledata
}

func (f FuncInfo) Valid() bool {
	return f._func != nil
}

func (f FuncInfo) Entry() uintptr {
	return f.datap.text + uintptr(f.entryoff)
}

func (f FuncInfo) Pcsp() uint32 {
	return f.pcsp
}

func (f FuncInfo) Datap() *moduledata {
	return f.datap
}

func (m *moduledata) PcTab() []byte {
	return m.pctab
}

func Step(p []byte, pc *uintptr, val *int32, first bool) (newp []byte, ok bool) {
	return step(p, pc, val, first)
}

func PCValue(f FuncInfo, off uint32, targetpc uintptr) (val int32, valPC uintptr, ok bool) {
	if off == 0 {
		return -1, 0, false
	}
	if !f.Valid() {
		return -1, 0, false
	}
	pcTab := f.Datap().PcTab()
	if len(pcTab) == 0 {
		return -1, 0, false
	}
	if off >= uint32(len(pcTab)) {
		return -1, 0, false
	}

	p := pcTab[off:]
	pc := f.Entry()
	prevpc := pc
	val = int32(-1)
	for {
		var stepOK bool
		p, stepOK = Step(p, &pc, &val, prevpc == f.Entry())
		if !stepOK {
			break
		}
		if targetpc < pc {
			return val, prevpc, true
		}
		prevpc = pc
	}

	return -1, 0, false
}

func FuncSPDelta(f FuncInfo, targetpc uintptr) (int32, bool) {
	val, _, ok := PCValue(f, f.Pcsp(), targetpc)
	return val, ok
}

func FindFuncMaxSPDelta(addr uint64) int32 {
	f := FindFunc(uintptr(addr))
	if f.Valid() {
		return FuncMaxSPDelta(f)
	}
	return 0
}

func FuncMaxSPDelta(f FuncInfo) int32 {

	if len(f.datap.pctab) == 0 {
		return 0
	}

	if f.pcsp >= uint32(len(f.datap.pctab)) {
		return 0
	}

	table := f.datap.pctab[f.pcsp:]
	pc := f.Entry()
	val := int32(-1)
	max := int32(0)
	first := true

	for {
		var ok bool
		table, ok = step(table, &pc, &val, first)
		if !ok {
			break
		}
		first = false
		if val > max {
			max = val
		}
	}
	return max
}


type funcFlag uint8

type functab struct {
	entryoff uint32
	funcoff  uint32
}

type textsect struct {
	vaddr    uintptr
	end      uintptr
	baseaddr uintptr
}

type nih struct{}

type NotInHeap struct{ _ nih }

type _func struct {
	NotInHeap

	entryoff uint32
	nameoff  int32

	args        int32
	deferreturn uint32

	pcsp      uint32
	pcfile    uint32
	pcln      uint32
	npcdata   uint32
	cuOffset  uint32
	startLine int32
	funcID    FuncID
	flag      funcFlag
	_         [1]byte
	nfuncdata uint8

}

type pcHeader struct {
	magic          uint32
	pad1, pad2     uint8
	minLC          uint8
	ptrSize        uint8
	nfunc          int
	nfiles         uint
	textStart      uintptr
	funcnameOffset uintptr
	cuOffset       uintptr
	filetabOffset  uintptr
	pctabOffset    uintptr
	pclnOffset     uintptr
}

type initTask struct {
	state uint32
	nfns  uint32
}

type moduledata struct {
	NotInHeap

	pcHeader     *pcHeader
	funcnametab  []byte
	cutab        []uint32
	filetab      []byte
	pctab        []byte
	pclntable    []byte
	ftab         []functab
	findfunctab  uintptr
	minpc, maxpc uintptr

	text, etext           uintptr
	noptrdata, enoptrdata uintptr
	data, edata           uintptr
	bss, ebss             uintptr
	noptrbss, enoptrbss   uintptr
	covctrs, ecovctrs     uintptr
	end, gcdata, gcbss    uintptr
	types, etypes         uintptr
	rodata                uintptr
	gofunc                uintptr // go.func.*

	textsectmap []textsect
	typelinks   []int32
	itablinks   []*itab

	ptab []ptabEntry

	pluginpath string
	pkghashes  []modulehash
}

type FuncID uint8

type ptabEntry struct {
	name nameOff
	typ  TypeOff
}

type nameOff int32
type TypeOff int32

type itab struct {
	inter *interfacetype
	_type *_type
	hash  uint32
	_     [4]byte
	fun   [1]uintptr
}

type _type struct {
	size       uintptr
	ptrdata    uintptr
	hash       uint32
	tflag      tflag
	align      uint8
	fieldAlign uint8
	kind       uint8

	equal func(unsafe.Pointer, unsafe.Pointer) bool

	gcdata    *byte
	str       nameOff
	ptrToThis TypeOff
}

type tflag uint8

type interfacetype struct {
	typ     _type
	pkgpath name
	mhdr    []imethod
}

type name struct {
	bytes *byte
}

type imethod struct {
	name nameOff
	ityp TypeOff
}

type modulehash struct {
	modulename   string
	linktimehash string
	runtimehash  *string
}
