//go:build !go1.23

package variable

import (
	"debug/dwarf"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"fmt"
	"os"
)

func LoadSelfDWARF() (*dwarf.Data, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	f, err := os.Open(exePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open executable: %w", err)
	}
	defer f.Close()

	if elfFile, err := elf.NewFile(f); err == nil {
		return elfFile.DWARF()
	}

	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}

	if machoFile, err := macho.NewFile(f); err == nil {
		return machoFile.DWARF()
	}

	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}

	if peFile, err := pe.NewFile(f); err == nil {
		return peFile.DWARF()
	}

	return nil, fmt.Errorf("failed to parse executable format (not ELF, Mach-O, or PE)")
}
