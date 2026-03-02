//go:build !go1.23

package module

import (
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"

	"github.com/0xbu11/codebull/pkg/debugflag"
	"golang.org/x/arch/x86/x86asm"
)

const (
	shieldMagic		= 0xDEADBEEF
	maxMappingEntries	= 65535
	maxTrampolineEntries	= 65535
	shieldBaseOffset	= 64
	funcEndPadding		= 16
	ptrSize			= 8
	minfunc			= 16
	pcbucketsize		= 256 * minfunc
	subbuckets		= 16
	subbucketsize		= pcbucketsize / subbuckets
	noFuncIdx		= int32(0x7fffffff)
)

type InjectionStrategy int

const (
	InjectNone	InjectionStrategy	= iota
	InjectStackDelta
	InjectInvalid
	InjectUnsafe
)

var keepAliveBuckets [][]findfuncbucket
var keepAliveModules []*moduledata
var keepAliveFtabs [][]functab
var keepAliveByteSlices [][]byte
var keepAlivePCHeaders []*pcHeader

var patcherMutex sync.Mutex

var (
	pclnPool	[]byte
	pclnStartOffset	int
	pctabPool	[]byte
	poolMu		sync.Mutex
)

func initPools(md *moduledata) {
	poolMu.Lock()
	defer poolMu.Unlock()
	if len(pclnPool) == 0 {
		p1 := unsafe.Pointer(&md.pctab[0])
		p2 := unsafe.Pointer(&md.pclntable[0])

		if uintptr(p1) < uintptr(p2) {
			pclnStartOffset = int(uintptr(p2) - uintptr(p1))
			totalLen := pclnStartOffset + len(md.pclntable)
			pclnPool = make([]byte, totalLen)
			copy(pclnPool, md.pctab)
			dstPcln := pclnPool[pclnStartOffset:]
			copy(dstPcln, md.pclntable)
		} else {
			pclnPool = make([]byte, len(md.pclntable))
			copy(pclnPool, md.pclntable)
			pclnStartOffset = 0
		}
	}
	if len(pctabPool) == 0 {
		pctabPool = make([]byte, len(md.pctab))
		copy(pctabPool, md.pctab)
	}
}

type pcMapEntry struct {
	Orig	uint32
	New	uint32
}

type TrampolineInfo struct {
	StartOffset	uint32
	EndOffset	uint32
	StackDelta	uint32
}

func getPCMapping(base uintptr) ([]pcMapEntry, uint32) {
	shieldBase := base + shieldBaseOffset
	magic := *(*uint32)(unsafe.Pointer(shieldBase))
	if magic != shieldMagic {
		return nil, 0
	}
	count := *(*uint32)(unsafe.Pointer(shieldBase + 4))
	if count > maxMappingEntries {
		count = maxMappingEntries
	}
	mapping := make([]pcMapEntry, count)
	for i := uint32(0); i < count; i++ {
		mapping[i].Orig = *(*uint32)(unsafe.Pointer(shieldBase + 8 + uintptr(i)*ptrSize))
		mapping[i].New = *(*uint32)(unsafe.Pointer(shieldBase + 12 + uintptr(i)*ptrSize))
	}
	return mapping, count
}

func getTrampolines(base uintptr, mappingCount uint32) []TrampolineInfo {
	shieldBase := base + shieldBaseOffset
	trampBase := shieldBase + 8 + uintptr(mappingCount)*8
	count := *(*uint32)(unsafe.Pointer(trampBase))
	if count > maxTrampolineEntries {
		count = maxTrampolineEntries
	}
	trampolines := make([]TrampolineInfo, count)
	for i := uint32(0); i < count; i++ {
		entryBase := trampBase + 4 + uintptr(i)*12
		trampolines[i].StartOffset = *(*uint32)(unsafe.Pointer(entryBase))
		trampolines[i].EndOffset = *(*uint32)(unsafe.Pointer(entryBase + 4))
		trampolines[i].StackDelta = *(*uint32)(unsafe.Pointer(entryBase + 8))
	}
	return trampolines
}

func PatchModule(origEntry uint64, newEntry, newEnd uint64, prologueShift int) error {
	origFunc := FindFunc(origEntry)
	if origFunc == nil {
		return fmt.Errorf("original function not found at 0x%x", origEntry)
	}

	debugflag.Printf("PATCHER: OrigFunc: %s PclntableLen: %d PctabLen: %d", funcname(*origFunc), len(origFunc.datap.pclntable), len(origFunc.datap.pctab))

	newEnd += funcEndPadding
	delta := int64(newEntry) - int64(origEntry)
	initPools(origFunc.datap)
	newSize := uint32(newEnd - newEntry)

	mapping, mappingCount := getPCMapping(uintptr(newEntry))
	trampolines := getTrampolines(uintptr(newEntry), mappingCount)

	newPcln, funcOffset, err := createPclnTable(*origFunc, delta, mapping, trampolines, newSize, prologueShift, uintptr(newEntry))
	if err != nil {
		return err
	}

	md := &moduledata{
		modulename:	fmt.Sprintf("shadow-0x%x", newEntry),
		text:		uintptr(newEntry),
		etext:		uintptr(newEnd),
		minpc:		uintptr(newEntry),
		maxpc:		uintptr(newEnd),

		funcnametab:	newPcln,
		cutab:		origFunc.datap.cutab,
		filetab:	origFunc.datap.filetab,
		pctab:		newPcln,
		pclntable:	newPcln,

		gcdata:		origFunc.datap.gcdata,
		gcbss:		origFunc.datap.gcbss,
		gcdatamask:	origFunc.datap.gcdatamask,
		gcbssmask:	origFunc.datap.gcbssmask,
		pluginpath:	origFunc.datap.pluginpath,

		gofunc:	origFunc.datap.gofunc,
		end:	uintptr(unsafe.Pointer(&newPcln[0])) + uintptr(len(newPcln)),

		textsectmap:	nil,
	}

	patchedPCHeader := new(pcHeader)
	*patchedPCHeader = *origFunc.datap.pcHeader
	patchedPCHeader.nfunc = 1
	patchedPCHeader.textStart = md.text

	headerAddr := uintptr(unsafe.Pointer(patchedPCHeader))
	getOff := func(slice []byte) uintptr {
		if len(slice) > 0 {
			return uintptr(unsafe.Pointer(&slice[0])) - headerAddr
		}
		return 0
	}

	patchedPCHeader.funcnameOffset = getOff(md.funcnametab)
	patchedPCHeader.filetabOffset = getOff(md.filetab)
	patchedPCHeader.pctabOffset = getOff(md.pctab)
	patchedPCHeader.pclnOffset = getOff(md.pclntable)

	if len(md.cutab) > 0 {
		patchedPCHeader.cuOffset = uintptr(unsafe.Pointer(&md.cutab[0])) - headerAddr
	} else {
		patchedPCHeader.cuOffset = 0
	}

	md.pcHeader = patchedPCHeader
	relFuncOffset := uint32(funcOffset)

	ftab := []functab{
		{entryoff: 0, funcoff: relFuncOffset},
		{entryoff: uint32(newEnd - newEntry), funcoff: relFuncOffset},
	}
	md.ftab = ftab
	if err := createFindFuncBucket(md); err != nil {
		return err
	}

	patcherMutex.Lock()
	keepAliveFtabs = append(keepAliveFtabs, ftab)
	keepAliveModules = append(keepAliveModules, md)
	keepAlivePCHeaders = append(keepAlivePCHeaders, md.pcHeader)
	patcherMutex.Unlock()

	if err := verifyModule(md); err != nil {
		return fmt.Errorf("module verification failed: %w", err)
	}

	addModule(md)

	return nil
}

func verifyModule(md *moduledata) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during verification: %v", r)
		}
	}()
	debugflag.Printf("PATCHER: Verifying module %s [0x%x - 0x%x]", md.modulename, md.text, md.etext)

	if len(md.ftab) == 0 {
		return fmt.Errorf("module has empty ftab")
	}

	funcoff := md.ftab[0].funcoff
	if int(funcoff) >= len(md.pclntable) {
		return fmt.Errorf("funcoff %d out of bounds (len=%d)", funcoff, len(md.pclntable))
	}

	f := funcInfo{
		datap:	md,
		_func:	(*_func)(unsafe.Pointer(&md.pclntable[funcoff])),
	}
	if !f.valid() {
		return fmt.Errorf("invalid func info for module")
	}

	if err := verifyPCTableOffsets(f, md); err != nil {
		return err
	}

	if md.findfunctab != 0 {
		debugflag.Println("PATCHER: Verifying findfunc lookup...")
		for pc := md.text; pc < md.etext; pc += 256 {

		}
	}

	if err := verifyPCDecodingStrict(f, md); err != nil {
		return err
	}
	debugflag.Println("PATCHER: Verification successful")
	return nil
}

func verifyPCTableOffsets(f funcInfo, md *moduledata) error {
	checkPctabOffset := func(name string, off uint32) error {
		if off == 0 || off == 0xFFFFFFFF {
			return nil
		}
		if int(off) >= len(md.pctab) {
			return fmt.Errorf("%s offset out of bounds: off=%d pctab_len=%d", name, off, len(md.pctab))
		}
		return nil
	}

	if err := checkPctabOffset("pcsp", f.pcsp); err != nil {
		return err
	}
	if err := checkPctabOffset("pcfile", f.pcfile); err != nil {
		return err
	}
	if err := checkPctabOffset("pcln", f.pcln); err != nil {
		return err
	}

	pcdataBase := uintptr(unsafe.Pointer(f._func)) + unsafe.Sizeof(_func{})
	for i := uint32(0); i < f.npcdata; i++ {
		off := *(*uint32)(unsafe.Pointer(pcdataBase + uintptr(i)*4))
		if err := checkPctabOffset(fmt.Sprintf("pcdata[%d]", i), off); err != nil {
			return err
		}
	}

	return nil
}

func verifyPCDecodingStrict(f funcInfo, md *moduledata) error {
	pcdataBase := uintptr(unsafe.Pointer(f._func)) + unsafe.Sizeof(_func{})

	for pc := md.text; pc < md.etext; pc++ {
		pcOff := pc - md.text

		if _, _, err := safePCValue(f, f.pcsp, pc); err != nil {
			return fmt.Errorf("pcsp decode failed at pc=0x%x off=0x%x: %w", pc, pcOff, err)
		}
		if _, _, err := safePCValue(f, f.pcfile, pc); err != nil {
			return fmt.Errorf("pcfile decode failed at pc=0x%x off=0x%x: %w", pc, pcOff, err)
		}
		if _, _, err := safePCValue(f, f.pcln, pc); err != nil {
			return fmt.Errorf("pcln decode failed at pc=0x%x off=0x%x: %w", pc, pcOff, err)
		}

		for table := uint32(0); table < f.npcdata; table++ {
			off := *(*uint32)(unsafe.Pointer(pcdataBase + uintptr(table)*4))
			if off == 0 || off == 0xFFFFFFFF {
				continue
			}
			if _, err := safePCDataValue1(f, table, pc); err != nil {
				return fmt.Errorf("pcdata[%d] decode failed at pc=0x%x off=0x%x: %w", table, pc, pcOff, err)
			}
		}
	}

	if md.etext > md.text {
		lastPC := md.etext - 1
		if _, _, err := safePCValue(f, f.pcsp, lastPC); err != nil {
			return fmt.Errorf("pcsp decode failed at last pc=0x%x off=0x%x: %w", lastPC, lastPC-md.text, err)
		}
	}

	return nil
}

func safePCValue(f funcInfo, off uint32, pc uintptr) (value int32, valuePC uintptr, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	value, valuePC = pcvalue(f, off, pc, true)
	return value, valuePC, nil
}

func safePCDataValue1(f funcInfo, table uint32, pc uintptr) (value int32, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()
	value = pcdatavalue1(f, table, pc, true)
	return value, nil
}

func createPclnTable(origFunc funcInfo, delta int64, mapping []pcMapEntry, trampolines []TrampolineInfo, newSize uint32, prologueShift int, newEntry uintptr) ([]byte, uintptr, error) {
	var newTablesData []byte
	newTablesData = append(newTablesData, 0)

	name := funcname(origFunc)
	shadowName := fmt.Sprintf("shadow-%s\x00", name)
	nameOffInBuffer := int32(len(newTablesData))
	newTablesData = append(newTablesData, []byte(shadowName)...)

	pFunc := origFunc._func
	funcSize := unsafe.Sizeof(_func{})
	npcdata := pFunc.npcdata
	nfuncdata := pFunc.nfuncdata

	pcdataBaseOrig := uintptr(unsafe.Pointer(pFunc)) + funcSize
	newPcDataOffsets := make([]uint32, npcdata)
	for i := uint32(0); i < npcdata; i++ {
		offset := *(*uint32)(unsafe.Pointer(pcdataBaseOrig + uintptr(i)*4))
		if offset == 0 || offset == 0xFFFFFFFF {
			newPcDataOffsets[i] = 0xFFFFFFFF
			continue
		}
		var strat InjectionStrategy = InjectNone
		if i == _PCDATA_UnsafePoint {
			strat = InjectUnsafe
		}
		oldBytes := readPclnBytes(origFunc.datap, offset, mapping, trampolines, newSize, prologueShift, strat, origFunc._func.entryOff, newEntry)
		newPcDataOffsets[i] = uint32(len(newTablesData))
		newTablesData = append(newTablesData, oldBytes...)
	}

	pcspBytes := readPclnBytes(origFunc.datap, origFunc._func.pcsp, mapping, trampolines, newSize, prologueShift, InjectStackDelta, origFunc._func.entryOff, newEntry)
	newPcspOffset := uint32(len(newTablesData))
	newTablesData = append(newTablesData, pcspBytes...)

	pcfileBytes := readPclnBytes(origFunc.datap, origFunc._func.pcfile, mapping, trampolines, newSize, prologueShift, InjectNone, origFunc._func.entryOff, newEntry)
	newPcfileOffset := uint32(len(newTablesData))
	newTablesData = append(newTablesData, pcfileBytes...)

	pclnBytes := readPclnBytes(origFunc.datap, origFunc._func.pcln, mapping, trampolines, newSize, prologueShift, InjectNone, origFunc._func.entryOff, newEntry)
	newPclnOffset := uint32(len(newTablesData))
	newTablesData = append(newTablesData, pclnBytes...)

	pad := (4 - (len(newTablesData) % 4)) % 4
	newTablesData = append(newTablesData, make([]byte, pad)...)
	funcOffset := uintptr(len(newTablesData))
	newFunc := *pFunc
	newFunc.entryOff = 0
	newFunc.nameOff = nameOffInBuffer
	newFunc.pcsp = newPcspOffset
	newFunc.pcfile = newPcfileOffset
	newFunc.pcln = newPclnOffset

	funcBytes := unsafe.Slice((*byte)(unsafe.Pointer(&newFunc)), funcSize)
	newTablesData = append(newTablesData, funcBytes...)

	for _, off := range newPcDataOffsets {
		offBytes := (*[4]byte)(unsafe.Pointer(&off))[:]
		newTablesData = append(newTablesData, offBytes...)
	}

	funcdataBaseOrig := pcdataBaseOrig + uintptr(npcdata)*4
	for i := uint8(0); i < nfuncdata; i++ {
		off := *(*uint32)(unsafe.Pointer(funcdataBaseOrig + uintptr(i)*4))
		offBytes := (*[4]byte)(unsafe.Pointer(&off))[:]
		newTablesData = append(newTablesData, offBytes...)
	}
	return newTablesData, funcOffset, nil
}

func readPclnBytes(datap *moduledata, offset uint32, mapping []pcMapEntry, trampolines []TrampolineInfo, newSize uint32, prologueShift int, strategy InjectionStrategy, funcEntryOff uint32, newEntry uintptr) []byte {
	if offset == 0 || offset == 0xFFFFFFFF {
		return nil
	}
	src := datap.pctab[offset:]
	entries := decodePCDataEntries(src)
	origEntries := append([]PCDataEntry(nil), entries...)

	if len(mapping) > 0 && len(entries) > 0 {
		for i := range entries {
			origOff := uint32(entries[i].Offset)
			found := false
			for j := len(mapping) - 1; j >= 0; j-- {
				if mapping[j].Orig <= origOff {
					delta := mapping[j].New - mapping[j].Orig
					entries[i].Offset = uintptr(origOff + delta)
					found = true
					break
				}
			}
			if !found {
				entries[i].Offset += uintptr(prologueShift)
			}
		}
	} else if len(entries) > 0 {
		for i := range entries {
			entries[i].Offset += uintptr(prologueShift)
		}
	}

	if len(entries) > 0 && entries[0].Offset > 0 {
		entries = append([]PCDataEntry{{Offset: 0, Value: entries[0].Value}}, entries...)
	}

	sort.Slice(trampolines, func(i, j int) bool {
		return trampolines[i].StartOffset < trampolines[j].StartOffset
	})

	applyTrampolines := len(trampolines) > 0 && len(entries) > 0

	if applyTrampolines {
		type entrySource uint8
		const (
			sourceOriginal	entrySource	= iota
			sourceTrampStart
			sourceTrampEnd
			sourceTrampBody
		)
		type stagedEntry struct {
			Offset	uintptr
			Value	int32
			Source	entrySource
			Order	int
		}

		sourceName := func(s entrySource) string {
			switch s {
			case sourceTrampStart:
				return "tramp_start"
			case sourceTrampEnd:
				return "tramp_end"
			case sourceTrampBody:
				return "tramp_body"
			default:
				return "original"
			}
		}

		sourcePriority := func(s entrySource) int {
			switch s {
			case sourceTrampStart:
				return 40
			case sourceTrampBody:
				return 38
			case sourceTrampEnd:
				return 35
			default:
				return 10
			}
		}

		var staged []stagedEntry
		orderCounter := 0
		appendStaged := func(offset uintptr, value int32, source entrySource) {
			staged = append(staged, stagedEntry{Offset: offset, Value: value, Source: source, Order: orderCounter})
			orderCounter++
		}

		entIdx := 0
		for tIdx := range trampolines {
			t := trampolines[tIdx]
			tStart := uintptr(t.StartOffset)
			tEnd := uintptr(t.EndOffset)
			for entIdx < len(entries) && entries[entIdx].Offset < tStart {
				e := entries[entIdx]
				if strategy == InjectInvalid {
					e.Value = -1
				}
				appendStaged(e.Offset, e.Value, sourceOriginal)
				entIdx++
			}
			var valStart int32 = -1
			for j := 0; j < len(entries); j++ {
				if entries[j].Offset > tStart {
					break
				}
				valStart = entries[j].Value
			}

			var valEnd int32 = valStart
			for j := 0; j < len(entries); j++ {
				if entries[j].Offset > tEnd {
					break
				}
				valEnd = entries[j].Value
			}
			if strategy == InjectStackDelta {
				if rebuilt, ok := rebuildPCSPForTrampoline(newEntry, t, valStart, valEnd); ok && len(rebuilt) > 0 {
					for _, e := range rebuilt {
						appendStaged(e.Offset, e.Value, sourceTrampBody)
					}
				} else {
					bodyVal := valStart + int32(t.StackDelta)
					appendStaged(tStart, bodyVal, sourceTrampStart)
					appendStaged(tEnd, valEnd, sourceTrampEnd)
				}
			} else if strategy == InjectInvalid {
				appendStaged(tStart, -1, sourceTrampStart)
				appendStaged(tEnd, valEnd, sourceTrampEnd)
			} else if strategy == InjectUnsafe {
				appendStaged(tStart, -2, sourceTrampStart)
				appendStaged(tEnd, valEnd, sourceTrampEnd)
			} else {
				appendStaged(tStart, valStart, sourceTrampStart)
			}
			for entIdx < len(entries) && entries[entIdx].Offset < tEnd {
				entIdx++
			}
		}
		for entIdx < len(entries) {
			e := entries[entIdx]
			if strategy == InjectInvalid {
				e.Value = -1
			}
			appendStaged(e.Offset, e.Value, sourceOriginal)
			entIdx++
		}

		sort.SliceStable(staged, func(i, j int) bool {
			if staged[i].Offset == staged[j].Offset {
				return staged[i].Order < staged[j].Order
			}
			return staged[i].Offset < staged[j].Offset
		})

		merged := make([]PCDataEntry, 0, len(staged))
		if len(staged) > 0 {
			i := 0
			for i < len(staged) {
				j := i + 1
				winner := staged[i]
				for j < len(staged) && staged[j].Offset == staged[i].Offset {
					cand := staged[j]
					candPri := sourcePriority(cand.Source)
					winnerPri := sourcePriority(winner.Source)
					if candPri > winnerPri || (candPri == winnerPri && cand.Order > winner.Order) {
						winner = cand
					}
					j++
				}

				if j-i > 1 && debugflag.Enabled() {
					debugflag.Printf("PATCHER: pcdata offset collision at off=0x%x, group=%d winner=%s val=%d", winner.Offset, j-i, sourceName(winner.Source), winner.Value)
				}

				merged = append(merged, PCDataEntry{Offset: winner.Offset, Value: winner.Value})
				i = j
			}
		}

		entries = merged
	}

	if len(entries) > 0 {
		endOffset := uintptr(newSize)
		if entries[len(entries)-1].Offset < endOffset {
			entries = append(entries, PCDataEntry{Offset: endOffset, Value: entries[len(entries)-1].Value})
		}
	}

	if strategy == InjectStackDelta {
		debugPCSPAtOffset(entries, origEntries, mapping, trampolines, newSize, funcEntryOff)
	}

	encoded, _ := encodePCDataEntries(entries)
	return encoded
}

func rebuildPCSPForTrampoline(newEntry uintptr, tramp TrampolineInfo, startValue int32, endValue int32) ([]PCDataEntry, bool) {
	if runtime.GOARCH != "amd64" {
		return nil, false
	}
	if newEntry == 0 || tramp.EndOffset <= tramp.StartOffset {
		return nil, false
	}

	start := uintptr(tramp.StartOffset)
	end := uintptr(tramp.EndOffset)
	base := newEntry + start
	regionLen := int(end - start)
	if regionLen <= 0 {
		return nil, false
	}

	var code []byte
	func() {
		defer func() {
			if recover() != nil {
				code = nil
			}
		}()
		code = unsafe.Slice((*byte)(unsafe.Pointer(base)), regionLen)
	}()
	if len(code) == 0 {
		return nil, false
	}

	entries := make([]PCDataEntry, 0, 8)
	entries = append(entries, PCDataEntry{Offset: start, Value: startValue})
	current := startValue
	off := 0
	for off < len(code) {
		inst, err := x86asm.Decode(code[off:], 64)
		if err != nil || inst.Len <= 0 {
			return nil, false
		}
		delta := amd64StackDelta(inst)
		next := current + int32(delta)
		if next != current {
			entries = append(entries, PCDataEntry{Offset: start + uintptr(off) + uintptr(inst.Len), Value: current})
			current = next
		}
		off += inst.Len
	}

	entries = append(entries, PCDataEntry{Offset: end, Value: endValue})
	return compactPCDataEntries(entries), true
}

func amd64StackDelta(inst x86asm.Inst) int {
	op := inst.Op.String()
	if strings.HasPrefix(op, "PUSH") {
		return ptrSize
	}
	if strings.HasPrefix(op, "POP") {
		return -ptrSize
	}

	if op == "SUB" {
		if reg, ok := inst.Args[0].(x86asm.Reg); ok && (reg == x86asm.RSP || reg == x86asm.ESP) {
			if imm, ok := x86Imm(inst.Args[1]); ok {
				return int(imm)
			}
		}
	}
	if op == "ADD" {
		if reg, ok := inst.Args[0].(x86asm.Reg); ok && (reg == x86asm.RSP || reg == x86asm.ESP) {
			if imm, ok := x86Imm(inst.Args[1]); ok {
				return -int(imm)
			}
		}
	}
	if op == "LEAVE" {
		return -ptrSize
	}
	if strings.HasPrefix(op, "RET") {
		if imm, ok := x86Imm(inst.Args[0]); ok {
			return -ptrSize - int(imm)
		}
		return -ptrSize
	}

	return 0
}

func x86Imm(arg x86asm.Arg) (int64, bool) {
	imm, ok := arg.(x86asm.Imm)
	if !ok {
		return 0, false
	}
	return int64(imm), true
}

func compactPCDataEntries(entries []PCDataEntry) []PCDataEntry {
	if len(entries) == 0 {
		return entries
	}
	compacted := make([]PCDataEntry, 0, len(entries))
	for _, e := range entries {
		if len(compacted) == 0 {
			compacted = append(compacted, e)
			continue
		}
		last := compacted[len(compacted)-1]
		if last.Offset == e.Offset {
			compacted[len(compacted)-1] = e
			continue
		}
		if last.Value == e.Value {
			continue
		}
		compacted = append(compacted, e)
	}
	return compacted
}

func debugPCSPAtOffset(entries []PCDataEntry, origEntries []PCDataEntry, mapping []pcMapEntry, trampolines []TrampolineInfo, newSize uint32, funcEntryOff uint32) {
	if os.Getenv("EGO_SHADOW_DEBUG_PCSP") != "1" {
		return
	}

	raw := os.Getenv("EGO_SHADOW_DEBUG_PCSP_OFF")
	if raw == "" {
		debugflag.Printf("PATCHER: pcsp debug enabled, set EGO_SHADOW_DEBUG_PCSP_OFF to inspect target offset (entryOff=0x%x size=0x%x entries=%d trampolines=%d)", funcEntryOff, newSize, len(entries), len(trampolines))
		return
	}

	target, err := strconv.ParseUint(raw, 0, 64)
	if err != nil {
		debugflag.Printf("PATCHER: invalid EGO_SHADOW_DEBUG_PCSP_OFF=%q: %v", raw, err)
		return
	}
	targetOff := uintptr(target)

	value := int32(-1)
	activeEntryIdx := -1
	for i := 0; i < len(entries); i++ {
		if entries[i].Offset > targetOff {
			break
		}
		value = entries[i].Value
		activeEntryIdx = i
	}

	trampMsg := "none"
	for i := range trampolines {
		t := trampolines[i]
		start := uintptr(t.StartOffset)
		end := uintptr(t.EndOffset)
		if targetOff >= start && targetOff < end {
			trampMsg = fmt.Sprintf("idx=%d [0x%x,0x%x) delta=%d", i, t.StartOffset, t.EndOffset, t.StackDelta)
			break
		}
	}

	debugflag.Printf("PATCHER: pcsp probe targetOff=0x%x value=%d entryIdx=%d entryOff=0x%x size=0x%x tramp=%s", targetOff, value, activeEntryIdx, funcEntryOff, newSize, trampMsg)

	origOff := uint32(0)
	origMapped := false
	if len(mapping) > 0 {
		for j := len(mapping) - 1; j >= 0; j-- {
			m := mapping[j]
			if uint32(targetOff) >= m.New {
				origOff = m.Orig + (uint32(targetOff) - m.New)
				origMapped = true
				break
			}
		}
	}

	origVal := int32(-1)
	origIdx := -1
	if len(origEntries) > 0 {
		probeOrigOff := targetOff
		if origMapped {
			probeOrigOff = uintptr(origOff)
		}
		for i := 0; i < len(origEntries); i++ {
			if origEntries[i].Offset > probeOrigOff {
				break
			}
			origVal = origEntries[i].Value
			origIdx = i
		}
	}

	if origMapped {
		debugflag.Printf("PATCHER: pcsp inverse-map targetOff=0x%x -> origOff=0x%x origVal=%d origIdx=%d", targetOff, origOff, origVal, origIdx)
	} else {
		debugflag.Printf("PATCHER: pcsp inverse-map targetOff=0x%x -> no mapping lower-bound (origVal=%d origIdx=%d)", targetOff, origVal, origIdx)
	}

	if len(entries) == 0 {
		return
	}

	startIdx := activeEntryIdx - 2
	if startIdx < 0 {
		startIdx = 0
	}
	endIdx := activeEntryIdx + 2
	if endIdx >= len(entries) {
		endIdx = len(entries) - 1
	}
	for i := startIdx; i <= endIdx; i++ {
		debugflag.Printf("PATCHER: pcsp entry[%d] off=0x%x val=%d", i, entries[i].Offset, entries[i].Value)
	}
}

func createFindFuncBucket(md *moduledata) error {
	if len(md.ftab) < 2 {
		return fmt.Errorf("invalid ftab: expected at least 2 entries, got %d", len(md.ftab))
	}
	if md.maxpc <= md.minpc {
		return fmt.Errorf("invalid pc range: minpc=0x%x maxpc=0x%x", md.minpc, md.maxpc)
	}

	span := md.maxpc - md.minpc
	nSubbuckets := int((span + subbucketsize - 1) / subbucketsize)
	if nSubbuckets <= 0 {
		return fmt.Errorf("invalid subbucket count for span %d", span)
	}

	indexes := make([]int32, nSubbuckets)
	for i := range indexes {
		indexes[i] = noFuncIdx
	}

	for idx := 0; idx < len(md.ftab)-1; idx++ {
		p := md.text + uintptr(md.ftab[idx].entryoff)
		q := md.text + uintptr(md.ftab[idx+1].entryoff)
		if q <= p {
			continue
		}
		funcIdx := int32(idx)
		for cur := p; cur < q; cur += subbucketsize {
			i := int((cur - md.minpc) / subbucketsize)
			if i >= 0 && i < len(indexes) && indexes[i] > funcIdx {
				indexes[i] = funcIdx
			}
		}
		last := int((q - 1 - md.minpc) / subbucketsize)
		if last >= 0 && last < len(indexes) && indexes[last] > funcIdx {
			indexes[last] = funcIdx
		}
	}

	lastSeen := int32(-1)
	for i := range indexes {
		if indexes[i] == noFuncIdx {
			if lastSeen < 0 {
				return fmt.Errorf("hole in findfunctab at subbucket %d", i)
			}
			indexes[i] = lastSeen
			continue
		}
		lastSeen = indexes[i]
	}

	nBuckets := int((span + pcbucketsize - 1) / pcbucketsize)
	buckets := make([]findfuncbucket, nBuckets)
	for b := 0; b < nBuckets; b++ {
		baseSubbucket := b * subbuckets
		if baseSubbucket >= len(indexes) {
			break
		}
		base := indexes[baseSubbucket]
		if base == noFuncIdx {
			return fmt.Errorf("hole in findfunctab at bucket %d", b)
		}
		buckets[b].idx = uint32(base)
		for j := 0; j < subbuckets && baseSubbucket+j < len(indexes); j++ {
			idx := indexes[baseSubbucket+j]
			delta := idx - base
			if delta < 0 || delta >= 256 {
				return fmt.Errorf("findfunctab delta out of range at bucket %d subbucket %d: idx=%d base=%d", b, j, idx, base)
			}
			buckets[b].subbuckets[j] = byte(delta)
		}
	}

	patcherMutex.Lock()
	keepAliveBuckets = append(keepAliveBuckets, buckets)
	patcherMutex.Unlock()
	md.findfunctab = uintptr(unsafe.Pointer(&buckets[0]))
	return nil
}

func addModule(md *moduledata) {
	patcherMutex.Lock()
	defer patcherMutex.Unlock()

	var last *moduledata

	for p := &firstmoduledata; p != nil; p = p.next {
		if p == md {
			debugflag.Printf("PATCHER: Module %s already registered at %p.", md.modulename, unsafe.Pointer(md))
			return
		}
		last = p
	}

	if last != nil {
		debugflag.Printf("PATCHER: Linking module %s (0x%x) to last module %s (0x%x)", md.modulename, md.text, last.modulename, last.text)
		last.next = md
		lastmoduledatap = md
	} else {
		debugflag.Println("PATCHER: Critical error: firstmoduledata list traversal failed, last is nil")
		return
	}

	modulesinit()

	mods := activeModules()
	found := false
	for _, m := range mods {
		if m == md {
			found = true
			break
		}
	}
	if found {
		debugflag.Printf("PATCHER: Success! Module %s (0x%x) found in activeModules", md.modulename, md.text)
	} else {
		debugflag.Printf("PATCHER: ERROR! Module %s (0x%x) NOT found in activeModules", md.modulename, md.text)
	}
}

func decodeFunc(f *_func) (pcsp, pcfile, pcln uint32, npcdata uint32, nfuncdata uint8) {
	return f.pcsp, f.pcfile, f.pcln, f.npcdata, f.nfuncdata
}
