//go:build !go1.23

package module

import "unsafe"


type moduledata struct {
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
	typelinks   []int32          // offsets from types
	itablinks   []unsafe.Pointer // []*itab

	ptab []ptabEntry

	pluginpath string
	pkghashes  []modulehash
	inittasks  []*initTask

	modulename   string
	modulehashes []modulehash

	hasmain uint8 // 1 if module contains the main function, 0 otherwise

	gcdatamask, gcbssmask bitvector

	typemap map[int32]unsafe.Pointer // map[typeOff]*_type

	bad bool // module failed to load and should be ignored

	next *moduledata
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

type functab struct {
	entryoff uint32 // relative to runtime.text
	funcoff  uint32
}

type textsect struct {
	vaddr    uintptr // prelinked section vaddr
	end      uintptr // vaddr + section length
	baseaddr uintptr // relocated section address
}

type ptabEntry struct {
	name int32
	typ  int32
}

type modulehash struct {
	modulename   string
	linktimehash string
	runtimehash  *string
}

type initTask struct {
	state uint32
	nfns  uint32
}

type bitvector struct {
	n        int32 // number of bits
	bytedata *uint8
}

type _func struct {
	entryOff uint32 // start pc, as offset from moduledata.text/pcHeader.textStart
	nameOff  int32  // function name

	args        int32  // in/out args size
	deferreturn uint32 // offset of start of a deferreturn call instruction from entry, if any.

	pcsp      uint32
	pcfile    uint32
	pcln      uint32
	npcdata   uint32
	cuOffset  uint32 // runtime.cutab offset of this function's CU
	startLine int32  // line number of start of function (func keyword/TEXT directive)
	funcID    uint8  // set for certain special runtime functions
	flag      uint8
	_         [1]byte // pad
	nfuncdata uint8   // must be last, must end on a uint32-boundary

}

type funcInfo struct {
	*_func
	datap *moduledata
}

type findfuncbucket struct {
	idx        uint32
	subbuckets [16]byte
}

const (
	_PCDATA_UnsafePoint   = 0
	_PCDATA_StackMapIndex = 1
	_PCDATA_InlTreeIndex  = 2
	_PCDATA_ArgLiveIndex  = 3

	_FUNCDATA_ArgsPointerMaps    = 0
	_FUNCDATA_LocalsPointerMaps  = 1
	_FUNCDATA_StackObjects       = 2
	_FUNCDATA_InlTree            = 3
	_FUNCDATA_OpenCodedDeferInfo = 4
	_FUNCDATA_ArgInfo            = 5
	_FUNCDATA_ArgLiveInfo        = 6
	_FUNCDATA_WrapInfo           = 7

	_ArgsSizeUnknown = -0x80000000
)

const (
	_PCDATA_UnsafePointSafe   = -1 // Safe for async preemption
	_PCDATA_UnsafePointUnsafe = -2 // Unsafe for async preemption

)

