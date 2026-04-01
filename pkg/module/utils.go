//go:build !go1.23

package module

import "unsafe"

//go:linkname activeModules runtime.activeModules
func activeModules() []*moduledata

//go:linkname lastmoduledatap runtime.lastmoduledatap
var lastmoduledatap *moduledata

//go:linkname firstmoduledata runtime.firstmoduledata
var firstmoduledata moduledata

//go:linkname modulesinit runtime.modulesinit
func modulesinit()

func GetModules() []*moduledata {
	return activeModules()
}

//go:linkname findfunc runtime.findfunc
func findfunc(pc uintptr) funcInfo

//go:linkname funcname runtime.funcname
func funcname(f funcInfo) string

//go:linkname step runtime.step
func step(p []byte, pc *uintptr, val *int32, first bool) (newp []byte, ok bool)

//go:linkname pcdatavalue1 runtime.pcdatavalue1
func pcdatavalue1(f funcInfo, table uint32, targetpc uintptr, strict bool) int32

//go:linkname funcdata runtime.funcdata
func funcdata(f funcInfo, i uint8) unsafe.Pointer

//go:linkname pcvalue runtime.pcvalue
func pcvalue(f funcInfo, off uint32, targetpc uintptr, strict bool) (int32, uintptr)

//go:linkname funcline1 runtime.funcline1
func funcline1(f funcInfo, targetpc uintptr, strict bool) (file string, line int32)

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
