//go:build !go1.23

package guard

import (
	"fmt"
	"unsafe"
	_ "unsafe" // For linkname
)

func Check(start, end uint64) error {
	lock(&allglock)
	defer unlock(&allglock)

	for _, gp := range allgs {
		if gp == nil {
			continue
		}

		pc := gp.sched.pc
		if uint64(pc) >= start && uint64(pc) < end {
			return fmt.Errorf("goroutine %d is executing at 0x%x, which is inside [0x%x, 0x%x)", gp.goid, pc, start, end)
		}
	}

	return nil
}

//go:linkname allgs runtime.allgs
var allgs []*g

//go:linkname allglock runtime.allglock
var allglock mutex

//go:linkname lock runtime.lock
func lock(l *mutex)

//go:linkname unlock runtime.unlock
func unlock(l *mutex)


type mutex struct {
	key uintptr
}

type g struct {
	stack       stack   // offset known to runtime
	stackguard0 uintptr // offset known to liblink
	stackguard1 uintptr // offset known to liblink

	_panic    uintptr // *_panic
	_defer    uintptr // *_defer
	m         uintptr // *m
	sched     gobuf
	syscallsp uintptr // if status==Gsyscall, syscallsp = sched.sp to use during gc
	syscallpc uintptr // if status==Gsyscall, syscallpc = sched.pc to use during gc
	stktopsp  uintptr // expected sp at top of stack, to check in traceback

	param        unsafe.Pointer
	atomicstatus uint32
	stackLock    uint32
	goid         int64
}

type stack struct {
	lo uintptr
	hi uintptr
}

type gobuf struct {
	sp   uintptr
	pc   uintptr
	g    uintptr
	ctxt uintptr
	ret  uintptr
	lr   uintptr
	bp   uintptr
}
