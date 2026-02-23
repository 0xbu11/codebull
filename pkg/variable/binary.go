//go:build !go1.23

package variable

import (
	"debug/elf"
	"fmt"
	"os"
)

type BinaryReader struct {
	file *os.File
	elf  *elf.File
}

func NewBinaryReader() (*BinaryReader, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %w", err)
	}

	f, err := os.Open(exePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open executable: %w", err)
	}

	elfFile, err := elf.NewFile(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("failed to parse ELF: %w", err)
	}

	return &BinaryReader{
		file: f,
		elf:  elfFile,
	}, nil
}

func (r *BinaryReader) ReadInstructions(addr uint64, size int) ([]byte, error) {
	for _, sect := range r.elf.Sections {
		if sect.Type != elf.SHT_PROGBITS {
			continue
		}
		if addr >= sect.Addr && addr < sect.Addr+sect.Size {
			offset := int64(addr - sect.Addr)
			b := make([]byte, size)
			n, err := sect.ReadAt(b, offset)
			if err != nil {
				return nil, err
			}
			return b[:n], nil
		}
	}
	return nil, fmt.Errorf("address 0x%x not found in text sections", addr)
}

func (r *BinaryReader) Close() error {
	r.elf.Close()
	return r.file.Close()
}
