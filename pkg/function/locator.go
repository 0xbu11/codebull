//go:build !go1.23

package function

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/0xbu11/codebull/pkg/debugflag"
	"github.com/0xbu11/codebull/pkg/variable"
)

type Locator struct {
	Data     *dwarf.Data
	Reader   *variable.BinaryReader
	DebugLoc []byte
}

func NewLocator(data *dwarf.Data, reader *variable.BinaryReader, debugLoc []byte) *Locator {
	return &Locator{
		Data:     data,
		Reader:   reader,
		DebugLoc: debugLoc,
	}
}

func NewLocatorForSelf() (*Locator, error) {
	path, err := os.Executable()
	if err != nil {
		path = "/proc/self/exe"
	}

	debugflag.Printf("NewLocatorForSelf: Opening executable: %s", path)
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open executable: %v", err)
	}
	defer f.Close()

	debugflag.Println("NewLocatorForSelf: Reading DWARF...")
	d, err := f.DWARF()
	if err != nil {
		return nil, fmt.Errorf("failed to read DWARF: %v", err)
	}
	debugflag.Println("NewLocatorForSelf: DWARF read successfully")

	var debugLoc []byte
	if sec := f.Section(".debug_loc"); sec != nil {
		debugLoc, _ = sec.Data()
	}

	return NewLocator(d, nil, debugLoc), nil
}

func (l *Locator) GetFunction(funcName string) (*Function, error) {
	reader := l.Data.Reader()

	var cuBase uint64
	for {
		entry, err := reader.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if entry == nil {
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			if lowPC, ok := entry.Val(dwarf.AttrLowpc).(uint64); ok {
				cuBase = lowPC
			}
			continue
		}

		if entry.Tag == dwarf.TagSubprogram {
			name, ok := entry.Val(dwarf.AttrName).(string)
			if !ok {
				continue
			}

			match := false
			if name == funcName {
				match = true
			} else if strings.HasSuffix(name, "."+funcName) {
				match = true
			} else if strings.HasSuffix(name, "/"+funcName) { // unlikely for Go but possible
				match = true
			}

			if match {
				fn := &Function{
					Name:   name,
					Offset: entry.Offset,
				}

				if lowPC, ok := entry.Val(dwarf.AttrLowpc).(uint64); ok {
					fn.Entry = lowPC
				}

				if highPC, ok := entry.Val(dwarf.AttrHighpc).(uint64); ok {
					fn.End = highPC
				} else if highPC, ok := entry.Val(dwarf.AttrHighpc).(int64); ok {
					fn.End = fn.Entry + uint64(highPC)
				}

				if fn.Entry > 0 {
					fn.StackFrameSize = variable.FindFuncMaxSPDelta(fn.Entry)
				}

				if l.Reader != nil && fn.Entry > 0 {
					prologue, morestackAddr, err := AnalyzePrologue(l.Reader, fn.Entry)
					if err == nil {
						fn.Prologue = prologue
						fn.MorestackAddr = morestackAddr
					} else {
						debugflag.Printf("Prologue analysis failed: %v", err)
					}
				}

				vars, err := l.scanVariables(reader, entry, cuBase)
				if err != nil {
					return nil, err
				}
				fn.Variables = vars

				regsUsedMap := make(map[uint64]struct{})
				for _, v := range vars {
					regs, err := v.GetRegsUsed()
					if err == nil {
						for _, r := range regs {
							if _, exists := regsUsedMap[r]; !exists {
								regsUsedMap[r] = struct{}{}
								fn.RegsUsed = append(fn.RegsUsed, r)
							}
						}
					}
				}

				return fn, nil
			}
		}

		if entry.Children {
			reader.SkipChildren()
		}
	}

	return nil, fmt.Errorf("function not found: %s", funcName)
}

func (l *Locator) GetLineAddress(funcName string, line int) (uint64, error) {
	fn, err := l.GetFunction(funcName)
	if err != nil {
		return 0, err
	}
	if fn.Entry == 0 || fn.End == 0 {
		return 0, fmt.Errorf("function %s has no text range", funcName)
	}

	reader := l.Data.Reader()
	for {
		entry, err := reader.Next()
		if err != nil {
			return 0, err
		}
		if entry == nil {
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {



			ranges, err := l.Data.Ranges(entry)
			if err != nil {
				reader.SkipChildren()
				continue
			}

			foundCU := false
			for _, r := range ranges {
				if fn.Entry >= r[0] && fn.Entry < r[1] {
					foundCU = true
					break
				}
			}

			if foundCU {
				lr, err := l.Data.LineReader(entry)
				if err != nil {
					return 0, fmt.Errorf("failed to get line reader: %w", err)
				}
				if lr == nil {
					return 0, fmt.Errorf("no line table for CU")
				}

				var ent dwarf.LineEntry
				for {
					if err := lr.Next(&ent); err != nil {
						if err == io.EOF {
							break
						}
						return 0, err
					}

					if ent.Address < fn.Entry {
						continue
					}
					if ent.Address >= fn.End {
						break
					}

					if ent.Line == line {
						return ent.Address, nil
					}
				}
				return 0, fmt.Errorf("line %d not found in function %s (range 0x%x-0x%x)", line, funcName, fn.Entry, fn.End)
			}
		}

		if entry.Tag == dwarf.TagCompileUnit && entry.Children {
			reader.SkipChildren()
		}
	}

	return 0, fmt.Errorf("compile unit for function %s not found", funcName)
}

func (l *Locator) LocateVariables(funcName string, pc uint64) ([]*variable.Variable, error) {
	fn, err := l.GetFunction(funcName)
	if err != nil {
		return nil, err
	}
	return fn.Variables, nil
}

func (l *Locator) scanVariables(reader *dwarf.Reader, funcEntry *dwarf.Entry, base uint64) ([]*variable.Variable, error) {
	var variables []*variable.Variable

	if !funcEntry.Children {
		return nil, nil
	}

	depth := 1
	for {
		entry, err := reader.Next()
		if err != nil {
			return nil, err
		}
		if entry == nil {
			break
		}

		if entry.Tag == 0 {
			depth--
			if depth == 0 {
				break
			}
			continue
		}

		if entry.Children {
			depth++
		}

		if entry.Tag == dwarf.TagVariable || entry.Tag == dwarf.TagFormalParameter {
			name, _ := entry.Val(dwarf.AttrName).(string)
			if name == "" {
				continue
			}


			typeOffset, _ := entry.Val(dwarf.AttrType).(dwarf.Offset)
			typ, err := l.Data.Type(typeOffset)
			if err != nil {
			}

			locField := entry.Val(dwarf.AttrLocation)
			locDesc := ""

			var locBlock []byte
			var locList []variable.LocEntry

			if lb, ok := locField.([]byte); ok {
				locBlock = lb
				locDesc = "Simple Loc"
			} else if locOffset, ok := locField.(int64); ok {
				locDesc = fmt.Sprintf("LocList at 0x%x", locOffset)
				list, err := l.parseLocationList(locOffset, base)
				if err == nil {
					locList = list
				} else {
					locDesc += fmt.Sprintf(" (Parse Error: %v)", err)
				}
			} else {
				locDesc = "No Location Attribute"
			}

			v := variable.NewVariable(name, 0, typ, locDesc, locBlock)
			v.LocList = locList
			variables = append(variables, v)
		}
	}

	return variables, nil
}

func (l *Locator) parseLocationList(offset int64, base uint64) ([]variable.LocEntry, error) {
	if offset < 0 || int(offset) >= len(l.DebugLoc) {
		return nil, fmt.Errorf("invalid loc list offset %d", offset)
	}

	buf := bytes.NewBuffer(l.DebugLoc[offset:])
	var entries []variable.LocEntry
	currentBase := base

	for {
		var lowPC, highPC uint64
		if err := binary.Read(buf, binary.LittleEndian, &lowPC); err != nil {
			return nil, err
		}
		if err := binary.Read(buf, binary.LittleEndian, &highPC); err != nil {
			return nil, err
		}

		if lowPC == 0 && highPC == 0 {
			break
		}

		if lowPC == ^uint64(0) {
			currentBase = highPC
			continue
		}

		absLow := currentBase + lowPC
		absHigh := currentBase + highPC

		var length uint16
		if err := binary.Read(buf, binary.LittleEndian, &length); err != nil {
			return nil, err
		}

		loc := make([]byte, length)
		if _, err := buf.Read(loc); err != nil {
			return nil, err
		}

		entries = append(entries, variable.LocEntry{
			LowPC:  absLow,
			HighPC: absHigh,
			Loc:    loc,
		})
	}

	return entries, nil
}
