//go:build !go1.27

package trap

import (
	"math/bits"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"unsafe"
	_ "unsafe" // For linkname

	"github.com/0xbu11/codebull/pkg/debugflag"
	"github.com/0xbu11/codebull/pkg/duration"
)

//go:linkname nanotime runtime.nanotime
func nanotime() int64

var goidOffset atomic.Int64

const (
	goidScanMin = 8
	goidScanMax = 376
)

func init() {
	if off := discoverGoidOffset(); off > 0 {
		goidOffset.Store(off)
		duration.SetRuntimeHooks(CurGoid, nanotime)
		debugflag.Printf("goid offset discovered: %d", off)
	} else {
		debugflag.Printf("goid offset discovery failed; duration instrumentation disabled")
	}
}

//go:nosplit
func CurGoid() int64 {
	off := goidOffset.Load()
	if off == 0 {
		return 0
	}
	gp := getg()
	if gp == 0 {
		return 0
	}
	return *(*int64)(unsafe.Pointer(gp + uintptr(off)))
}

func goidFromStack() int64 {
	buf := make([]byte, 64)
	n := runtime.Stack(buf, false)
	s := strings.TrimPrefix(string(buf[:n]), "goroutine ")
	end := strings.IndexByte(s, ' ')
	if end <= 0 {
		return 0
	}
	id, err := strconv.ParseInt(s[:end], 10, 64)
	if err != nil {
		return 0
	}
	return id
}

func candidateMask() uint64 {
	gid := goidFromStack()
	if gid <= 0 {
		return 0
	}
	gp := getg()
	if gp == 0 {
		return 0
	}
	var mask uint64
	bit := 0
	for off := uintptr(goidScanMin); off <= goidScanMax; off += 8 {
		if *(*int64)(unsafe.Pointer(gp + off)) == gid {
			mask |= 1 << bit
		}
		bit++
	}
	return mask
}

func discoverGoidOffset() int64 {
	const probes = 3
	results := make(chan uint64, probes)
	for range probes {
		go func() { results <- candidateMask() }()
	}
	mask := ^uint64(0)
	for range probes {
		mask &= <-results
	}
	if mask == 0 || mask&(mask-1) != 0 {
		return 0
	}
	return int64(goidScanMin + 8*bits.TrailingZeros64(mask))
}
