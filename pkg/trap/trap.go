//go:build !go1.23

package trap

import (
	"os"
	"runtime/debug"
	"sync"
	"unsafe"
	_ "unsafe" // For linkname

	"github.com/0xbu11/codebull/pkg/debugflag"
	"github.com/0xbu11/codebull/pkg/harvest"
)

func getg() uintptr

//go:linkname systemstack runtime.systemstack
func systemstack(func())

var (
	collectOnce sync.Once
	collectCh   chan collectMessage
	harvestFn   = harvest.HarvestPoint
	recoverFn   = func(r any) {
		debugflag.Printf("Recovered panic in callback: %v", r)
	}

	gcBlockEnabled = os.Getenv("EGO_SHADOW_BLOCK_GC") != "0"
	gcMu           sync.Mutex
	gcBlockCount   int
	gcPrevPercent  int
)

func blockGC() {
	if !gcBlockEnabled {
		return
	}
	gcMu.Lock()
	defer gcMu.Unlock()
	if gcBlockCount == 0 {
		gcPrevPercent = debug.SetGCPercent(-1)
	}
	gcBlockCount++
}

func unblockGC() {
	if !gcBlockEnabled {
		return
	}
	gcMu.Lock()
	defer gcMu.Unlock()
	gcBlockCount--
	if gcBlockCount == 0 {
		debug.SetGCPercent(gcPrevPercent)
	}
}

type collectMessage struct {
	regs harvest.OnStackRegisters
	done chan struct{} // if non-nil, close when processing finishes
}

func startCollectorWorker() {
	collectCh = make(chan collectMessage, 1024)
	go func() {
		for msg := range collectCh {
			func() {
				defer func() {
					if r := recover(); r != nil {
						recoverFn(r)
					}
				}()
				harvestFn(&msg.regs)
			}()
			if msg.done != nil {
				close(msg.done)
			}
		}
	}()
}

func Handler(regs *harvest.OnStackRegisters) {
	regs.RSP_Dummy = uint64(uintptr(unsafe.Pointer(&regs.OldRBP))) + 8

	collectOnce.Do(startCollectorWorker)
	snapshot := *regs
	done := make(chan struct{})
	blockGC()
	defer unblockGC()
	collectCh <- collectMessage{regs: snapshot, done: done}
	<-done
}

func enqueueCollect(regs *harvest.OnStackRegisters) {
	collectOnce.Do(startCollectorWorker)
	snapshot := *regs
	select {
	case collectCh <- collectMessage{regs: snapshot}:
	default:
	}
}
