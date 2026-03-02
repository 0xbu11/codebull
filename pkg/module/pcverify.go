//go:build !go1.23

package module

import (
	"fmt"
	"runtime"
	"sort"
	"unsafe"

	"golang.org/x/arch/x86/x86asm"
)

func VerifyPatchedCallbackPCData(origEntry, shadowEntry uint64) error {
	origFunc := FindFunc(origEntry)
	if origFunc == nil {
		return fmt.Errorf("original function not found at 0x%x", origEntry)
	}
	shadowFunc := FindFunc(shadowEntry)
	if shadowFunc == nil {
		return fmt.Errorf("shadow function not found at 0x%x", shadowEntry)
	}

	mapping, mappingCount := getPCMapping(uintptr(shadowEntry))
	if len(mapping) == 0 {
		return fmt.Errorf("shadow mapping metadata missing at 0x%x", shadowEntry)
	}
	trampolines := getTrampolines(uintptr(shadowEntry), mappingCount)
	if len(trampolines) == 0 {
		return fmt.Errorf("shadow trampoline metadata missing at 0x%x", shadowEntry)
	}

	sorted := append([]pcMapEntry(nil), mapping...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].New == sorted[j].New {
			return sorted[i].Orig < sorted[j].Orig
		}
		return sorted[i].New < sorted[j].New
	})

	for i := range trampolines {
		tramp := trampolines[i]
		if tramp.EndOffset <= tramp.StartOffset {
			continue
		}

		origStartOff, ok := originalOffsetAtShadowOffset(sorted, tramp.StartOffset)
		if !ok {
			return fmt.Errorf("cannot resolve original offset for trampoline [%#x, %#x)", tramp.StartOffset, tramp.EndOffset)
		}

		origPC := uintptr(origEntry) + uintptr(origStartOff)
		shadowStartPC := uintptr(shadowEntry) + uintptr(tramp.StartOffset)
		shadowEndPC := uintptr(shadowEntry) + uintptr(tramp.EndOffset)

		if err := verifyTrampolinePCData(*origFunc, *shadowFunc, origPC, shadowStartPC, shadowEndPC); err != nil {
			return fmt.Errorf("trampoline [%#x, %#x) verification failed: %w", tramp.StartOffset, tramp.EndOffset, err)
		}

		if err := verifyTrampolinePCSP(*shadowFunc, uintptr(shadowEntry), tramp, shadowStartPC, shadowEndPC); err != nil {
			return fmt.Errorf("trampoline [%#x, %#x) pcsp verification failed: %w", tramp.StartOffset, tramp.EndOffset, err)
		}
	}

	return nil
}

func originalOffsetAtShadowOffset(mapping []pcMapEntry, shadowOff uint32) (uint32, bool) {
	idx := sort.Search(len(mapping), func(i int) bool {
		return mapping[i].New > shadowOff
	})
	if idx == 0 {
		return 0, false
	}
	return mapping[idx-1].Orig, true
}

func verifyTrampolinePCData(origFunc, shadowFunc funcInfo, origPC, shadowStartPC, shadowEndPC uintptr) error {
	maxTables := int(origFunc.npcdata)
	if int(shadowFunc.npcdata) < maxTables {
		maxTables = int(shadowFunc.npcdata)
	}

	for table := 0; table < maxTables; table++ {
		origValue, err := safePCDataValue1(origFunc, uint32(table), origPC)
		if err != nil {
			return fmt.Errorf("orig pcdata[%d] decode failed at pc=0x%x: %w", table, origPC, err)
		}

		for pc := shadowStartPC; pc < shadowEndPC; {
			newValue, err := safePCDataValue1(shadowFunc, uint32(table), pc)
			if err != nil {
				return fmt.Errorf("shadow pcdata[%d] decode failed at pc=0x%x: %w", table, pc, err)
			}

			if table == _PCDATA_UnsafePoint {
				if pc == shadowStartPC {
					if newValue != origValue {
						return fmt.Errorf("pcdata[%d] start mismatch at pc=0x%x: got %d want %d", table, pc, newValue, origValue)
					}
				} else if newValue != _PCDATA_UnsafePointUnsafe {
					return fmt.Errorf("pcdata[%d] at pc=0x%x = %d, want %d", table, pc, newValue, _PCDATA_UnsafePointUnsafe)
				}
			} else if newValue != origValue {
				return fmt.Errorf("pcdata[%d] mismatch at pc=0x%x: got %d want %d", table, pc, newValue, origValue)
			}

			instSize, sizeErr := instructionSizeAtPC(pc)
			if sizeErr != nil {
				return fmt.Errorf("instruction size read failed at pc=0x%x: %w", pc, sizeErr)
			}
			if instSize == 0 {
				return fmt.Errorf("instruction size is zero at pc=0x%x", pc)
			}
			pc += instSize
		}
	}

	return nil
}

func verifyTrampolinePCSP(shadowFunc funcInfo, shadowEntry uintptr, tramp TrampolineInfo, shadowStartPC, shadowEndPC uintptr) error {
	startValue, _, err := safePCValue(shadowFunc, shadowFunc.pcsp, shadowStartPC)
	if err != nil {
		return fmt.Errorf("read shadow pcsp start failed: %w", err)
	}
	endValue, _, err := safePCValue(shadowFunc, shadowFunc.pcsp, shadowEndPC)
	if err != nil {
		return fmt.Errorf("read shadow pcsp end failed: %w", err)
	}

	expectedEntries, ok := rebuildPCSPForTrampoline(shadowEntry, tramp, startValue, endValue)
	if !ok || len(expectedEntries) == 0 {
		if runtime.GOARCH == "amd64" {
			return fmt.Errorf("failed to rebuild expected pcsp entries")
		}
		return nil
	}

	for pc := shadowStartPC; pc < shadowEndPC; {
		got, _, err := safePCValue(shadowFunc, shadowFunc.pcsp, pc)
		if err != nil {
			return fmt.Errorf("read shadow pcsp failed at pc=0x%x: %w", pc, err)
		}
		expected := valueAtOffset(expectedEntries, pc-shadowEntry)
		if got != expected {
			return fmt.Errorf("pcsp mismatch at pc=0x%x: got %d want %d", pc, got, expected)
		}

		instSize, sizeErr := instructionSizeAtPC(pc)
		if sizeErr != nil {
			return fmt.Errorf("instruction size read failed at pc=0x%x: %w", pc, sizeErr)
		}
		if instSize == 0 {
			return fmt.Errorf("instruction size is zero at pc=0x%x", pc)
		}
		pc += instSize
	}

	return nil
}

func instructionSizeAtPC(pc uintptr) (uintptr, error) {
	if runtime.GOARCH != "amd64" {
		return 1, nil
	}

	const window = 15
	bytes := unsafe.Slice((*byte)(unsafe.Pointer(pc)), window)
	inst, err := x86asm.Decode(bytes, 64)
	if err != nil {
		return 0, err
	}
	if inst.Len <= 0 {
		return 0, fmt.Errorf("decode returned non-positive length")
	}
	return uintptr(inst.Len), nil
}
