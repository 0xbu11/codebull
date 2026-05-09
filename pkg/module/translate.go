//go:build !go1.27

package module

import (
	"runtime"
	"sort"

	"github.com/0xbu11/codebull/pkg/debugflag"
)

func GetOriginalPC(shadowPC uintptr) uintptr {
	fn := runtime.FuncForPC(shadowPC)
	if fn == nil {
		return shadowPC
	}

	entry := fn.Entry()
	mapping, count := GetPCMapping(entry)
	if len(mapping) == 0 {
		debugflag.Printf("TRANSLATE: No mapping found for shadow entry 0x%x (count=%d)", entry, count)
		return shadowPC
	}

	sorted := append([]PCMapEntry(nil), mapping...)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].New < sorted[j].New
	})

	shadowOff := uint32(shadowPC - entry)

	idx := sort.Search(len(sorted), func(i int) bool {
		return sorted[i].New > shadowOff
	})

	if idx == 0 {
		origFunc := FindFunc(uint64(entry))
		if origFunc != nil {
			return uintptr(origFunc.Entry()) + uintptr(shadowOff)
		}
		return shadowPC
	}

	match := sorted[idx-1]
	origOff := match.Orig + (shadowOff - match.New)

	origFunc := FindFunc(uint64(entry))
	if origFunc == nil {
		return shadowPC
	}

	resPC := uintptr(origFunc.Entry()) + uintptr(origOff)
	debugflag.Printf("TRANSLATE: shadowPC 0x%x -> origPC 0x%x", shadowPC, resPC)
	return resPC
}

