//go:build !go1.23

package trap

import (
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
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
	done *uint32
}

//go:nosplit
func ensureCollectorWorkerStarted() {
	collectOnce.Do(startCollectorWorker)
}

//go:nosplit
func startCollectorWorker() {
	collectCh = make(chan collectMessage, 1024)
	go func() {
		for msg := range collectCh {
			func() {
				defer func() {
					if r := recover(); r != nil {
						recoverFn(r)
					}
					if msg.done != nil {
						atomic.StoreUint32(msg.done, 1)
					}
				}()
				harvestFn(&msg.regs)
			}()
		}
	}()
}

//go:nosplit
func Handler(regs *harvest.OnStackRegisters) {
	if regs == nil {
		return
	}
	blockGC()
	snapshot := *regs
	snapshot.RSP_Dummy = uint64(uintptr(unsafe.Pointer(&regs.OldRBP))) + 8

	waitChan := make(chan struct{})

	defer unblockGC()

	systemstack(func() {
		go func(snapshot harvest.OnStackRegisters) {
			defer func() {
				if r := recover(); r != nil {
					recoverFn(r)
				}
				waitChan <- struct{}{}
			}()
			harvestFn(&snapshot)
		}(snapshot)
	})

	<-waitChan
}

func enqueueCollect(regs *harvest.OnStackRegisters) {
	ensureCollectorWorkerStarted()
	snapshot := *regs
	snapshot.RSP_Dummy = uint64(uintptr(unsafe.Pointer(&regs.OldRBP))) + 8
	select {
	case collectCh <- collectMessage{regs: snapshot, done: nil}:
	default:
	}
}
