//go:build !go1.27

package codebull

/*
#cgo CFLAGS: -I${SRCDIR}/../../cpp
#cgo CXXFLAGS: -I${SRCDIR}/../../cpp -I/usr/lib/llvm-18/include -std=c++17
#cgo LDFLAGS: -L${SRCDIR} -lcodebull_impl -L/usr/lib/llvm-18/lib -lLLVM-18 -lstdc++ -lm -lz -lpthread -ldl

#include "codebull.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"runtime"
	"sync/atomic"
	"unsafe"
)

const CopyFunctionLimitExceededCode = -1001

type CopyFunctionError struct {
	Code int
}

func (e *CopyFunctionError) Error() string {
	if e.Code == CopyFunctionLimitExceededCode {
		return "copy function hard limit exceeded"
	}
	return fmt.Sprintf("copy function failed: code %d", e.Code)
}

func (e *CopyFunctionError) Is(target error) bool {
	t, ok := target.(*CopyFunctionError)
	if !ok {
		return false
	}
	return e.Code == t.Code
}

var ErrCopyFunctionLimitExceeded = &CopyFunctionError{Code: CopyFunctionLimitExceededCode}

// CopyFunctionHardLimit is the number of copies one process is allowed. The
// enforcing counter lives in the native layer and is deliberately hard to
// reach; this is the same number, kept here only so the figure can be reported.
const CopyFunctionHardLimit = 20

// copyFunctionCalls counts the copies this process has asked for.
//
// The native counter only ever increments — releasing a tracepoint does not
// give the slot back — and it is not readable from outside, so a user could
// not see how much of the budget they had spent until a registration failed.
// This wrapper is the only caller of CopyFunction in the process, so counting
// here gives the same number without touching the enforcement path.
var copyFunctionCalls atomic.Int64

// CopyFunctionUsage reports how much of the per-process copy budget has been
// spent. Removing a tracepoint does not decrease `used`: the budget counts
// copies made, not points currently installed.
func CopyFunctionUsage() (used int, limit int, refundsOnRemoval bool) {
	return int(copyFunctionCalls.Load()), CopyFunctionHardLimit, false
}

func init() {
	version := C.CString(runtime.Version())
	defer C.free(unsafe.Pointer(version))
	C.reportShadowStartup(version)
}

func IsCopyFunctionLimitExceeded(err error) bool {
	return errors.Is(err, ErrCopyFunctionLimitExceeded)
}

func EnableShadowFunction(fromAddr, toAddr uint64) error {
	ret := C.enableShadowFunction(C.uint64_t(fromAddr), C.uint64_t(toAddr))
	if ret != 0 {
		return fmt.Errorf("enableShadowFunction failed with code %d", ret)
	}
	return nil
}

func CreateShadowFunction(start, end uint64, collectAddrs []uint64, collectorAddr uint64) ([]byte, uint64, int, error) {
	return CreateShadowFunctionFromBytes(start, end, nil, collectAddrs, collectorAddr)
}

func CreateShadowFunctionFromBytes(start, end uint64, sourceBytes []byte, collectAddrs []uint64, collectorAddr uint64) ([]byte, uint64, int, error) {
	sz := end - start
	if sz == 0 {
		return nil, 0, 0, fmt.Errorf("function size is 0")
	}

	funcBytes := sourceBytes
	if len(funcBytes) == 0 {
		src := (*[1 << 30]byte)(unsafe.Pointer(uintptr(start)))[:sz:sz]
		funcBytes = make([]byte, sz)
		copy(funcBytes, src)
	} else {
		if uint64(len(funcBytes)) < sz {
			return nil, 0, 0, fmt.Errorf("source bytes too short: have %d, need %d", len(funcBytes), sz)
		}
		funcBytes = funcBytes[:sz]
	}

	var newAddr unsafe.Pointer
	var newSize C.size_t
	var prologueShift C.size_t

	var cFuncBytes unsafe.Pointer
	var cFuncSize C.size_t
	if len(funcBytes) > 0 {
		cFuncBytes = unsafe.Pointer(&funcBytes[0])
		cFuncSize = C.size_t(len(funcBytes))
	}

	var cCollectAddrs unsafe.Pointer
	var cCollectCount C.size_t
	if len(collectAddrs) > 0 {
		cCollectAddrs = unsafe.Pointer(&collectAddrs[0])
		cCollectCount = C.size_t(len(collectAddrs))
	}
	var cCollectorAddr unsafe.Pointer
	if collectorAddr != 0 {
		cCollectorAddr = unsafe.Pointer(uintptr(collectorAddr))
	}

	// Count before the call, matching the native counter: it increments on
	// entry, so a rejected copy still spends a slot.
	copyFunctionCalls.Add(1)
	ret := C.CopyFunction(
		unsafe.Pointer(uintptr(start)),
		unsafe.Pointer(uintptr(end)),
		cFuncBytes,
		cFuncSize,
		&newAddr,
		&newSize,
		cCollectAddrs,
		cCollectCount,
		cCollectorAddr,
		&prologueShift,
	)
	if ret != 0 {
		code := int(ret)
		if code == CopyFunctionLimitExceededCode {
			return nil, 0, 0, ErrCopyFunctionLimitExceeded
		}
		return nil, 0, 0, &CopyFunctionError{Code: code}
	}

	length := int(newSize)
	slice := (*[1 << 30]byte)(newAddr)[:length:length]

	return slice, uint64(uintptr(newAddr)), int(prologueShift), nil
}
