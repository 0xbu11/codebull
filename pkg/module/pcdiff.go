//go:build !go1.23

package module

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
)

type PCTableDiffRow struct {
	OriginInstruction uintptr
	OriginValue       int32
	ShadowInstruction uintptr
	ShadowValue       int32
}

type PCTableDiffReport struct {
	PCSP   []PCTableDiffRow
	PCFile []PCTableDiffRow
	PCLN   []PCTableDiffRow
}

type PCValueFullRow struct {
	Index             int
	OriginOffset      uint32
	ShadowOffset      uint32
	OriginInstruction uintptr
	ShadowInstruction uintptr
	OriginPCSP        int32
	ShadowPCSP        int32
	OriginPCFile      int32
	ShadowPCFile      int32
	OriginPCLN        int32
	ShadowPCLN        int32
	OriginFile        string
	OriginLine        int32
	ShadowFile        string
	ShadowLine        int32
	OriginSource      string
	ShadowSource      string
}

func CompareOriginalShadowPCTables(origEntry, shadowEntry uint64) (*PCTableDiffReport, error) {
	origFunc := FindFunc(origEntry)
	if origFunc == nil {
		return nil, fmt.Errorf("original function not found at 0x%x", origEntry)
	}
	shadowFunc := FindFunc(shadowEntry)
	if shadowFunc == nil {
		return nil, fmt.Errorf("shadow function not found at 0x%x", shadowEntry)
	}

	mapping, _ := getPCMapping(uintptr(shadowEntry))
	if len(mapping) == 0 {
		return nil, fmt.Errorf("shadow mapping metadata missing at 0x%x", shadowEntry)
	}

	origPCSP := decodePCDataEntries(origFunc.datap.pctab[origFunc.pcsp:])
	shadowPCSP := decodePCDataEntries(shadowFunc.datap.pctab[shadowFunc.pcsp:])
	origPCFile := decodePCDataEntries(origFunc.datap.pctab[origFunc.pcfile:])
	shadowPCFile := decodePCDataEntries(shadowFunc.datap.pctab[shadowFunc.pcfile:])
	origPCLN := decodePCDataEntries(origFunc.datap.pctab[origFunc.pcln:])
	shadowPCLN := decodePCDataEntries(shadowFunc.datap.pctab[shadowFunc.pcln:])

	sorted := append([]pcMapEntry(nil), mapping...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Orig == sorted[j].Orig {
			return sorted[i].New < sorted[j].New
		}
		return sorted[i].Orig < sorted[j].Orig
	})

	report := &PCTableDiffReport{
		PCSP:   buildTableDiffRows(sorted, origPCSP, shadowPCSP, uintptr(origEntry), uintptr(shadowEntry)),
		PCFile: buildTableDiffRows(sorted, origPCFile, shadowPCFile, uintptr(origEntry), uintptr(shadowEntry)),
		PCLN:   buildTableDiffRows(sorted, origPCLN, shadowPCLN, uintptr(origEntry), uintptr(shadowEntry)),
	}

	return report, nil
}

func FormatPCTableDiffReport(report *PCTableDiffReport) string {
	if report == nil {
		return ""
	}

	var builder strings.Builder
	builder.WriteString(formatSingleDiffTable("pcsp", report.PCSP))
	builder.WriteString("\n\n")
	builder.WriteString(formatSingleDiffTable("pcfile", report.PCFile))
	builder.WriteString("\n\n")
	builder.WriteString(formatSingleDiffTable("pcln", report.PCLN))
	return builder.String()
}

func ListOriginalShadowPCValues(origEntry, shadowEntry uint64) ([]PCValueFullRow, error) {
	origFunc := FindFunc(origEntry)
	if origFunc == nil {
		return nil, fmt.Errorf("original function not found at 0x%x", origEntry)
	}
	shadowFunc := FindFunc(shadowEntry)
	if shadowFunc == nil {
		return nil, fmt.Errorf("shadow function not found at 0x%x", shadowEntry)
	}

	mapping, _ := getPCMapping(uintptr(shadowEntry))
	if len(mapping) == 0 {
		return nil, fmt.Errorf("shadow mapping metadata missing at 0x%x", shadowEntry)
	}

	sorted := append([]pcMapEntry(nil), mapping...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Orig == sorted[j].Orig {
			return sorted[i].New < sorted[j].New
		}
		return sorted[i].Orig < sorted[j].Orig
	})

	sourceCache := make(map[string][]string)
	rows := make([]PCValueFullRow, 0, len(sorted))
	seen := make(map[uint64]struct{}, len(sorted))

	for i, item := range sorted {
		key := (uint64(item.Orig) << 32) | uint64(item.New)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		origPC := uintptr(origEntry) + uintptr(item.Orig)
		shadowPC := uintptr(shadowEntry) + uintptr(item.New)

		origPCSP, _, _ := safePCValue(*origFunc, origFunc.pcsp, origPC)
		shadowPCSP, _, _ := safePCValue(*shadowFunc, shadowFunc.pcsp, shadowPC)
		origPCFile, _, _ := safePCValue(*origFunc, origFunc.pcfile, origPC)
		shadowPCFile, _, _ := safePCValue(*shadowFunc, shadowFunc.pcfile, shadowPC)
		origPCLN, _, _ := safePCValue(*origFunc, origFunc.pcln, origPC)
		shadowPCLN, _, _ := safePCValue(*shadowFunc, shadowFunc.pcln, shadowPC)

		origFile, origLine := safeFuncLine(*origFunc, origPC)
		shadowFile, shadowLine := safeFuncLine(*shadowFunc, shadowPC)

		rows = append(rows, PCValueFullRow{
			Index:             i,
			OriginOffset:      item.Orig,
			ShadowOffset:      item.New,
			OriginInstruction: origPC,
			ShadowInstruction: shadowPC,
			OriginPCSP:        origPCSP,
			ShadowPCSP:        shadowPCSP,
			OriginPCFile:      origPCFile,
			ShadowPCFile:      shadowPCFile,
			OriginPCLN:        origPCLN,
			ShadowPCLN:        shadowPCLN,
			OriginFile:        origFile,
			OriginLine:        origLine,
			ShadowFile:        shadowFile,
			ShadowLine:        shadowLine,
			OriginSource:      readSourceLine(sourceCache, origFile, origLine),
			ShadowSource:      readSourceLine(sourceCache, shadowFile, shadowLine),
		})
	}

	return rows, nil
}

func FormatPCValueFullList(rows []PCValueFullRow) string {
	var builder strings.Builder
	builder.WriteString("| idx | orig_off | shadow_off | origin instruction | shadow instruction | origin pcsp | shadow pcsp | origin pcfile | shadow pcfile | origin pcln | shadow pcln | origin source | shadow source |\n")
	builder.WriteString("|---:|---:|---:|---|---|---:|---:|---:|---:|---:|---:|---|---|\n")
	if len(rows) == 0 {
		builder.WriteString("| - | - | - | - | - | - | - | - | - | - | - | - | - |\n")
		return builder.String()
	}

	for _, row := range rows {
		originSrc := fmt.Sprintf("%s:%d %s", row.OriginFile, row.OriginLine, escapeMarkdownCell(row.OriginSource))
		shadowSrc := fmt.Sprintf("%s:%d %s", row.ShadowFile, row.ShadowLine, escapeMarkdownCell(row.ShadowSource))
		builder.WriteString(fmt.Sprintf("| %d | 0x%x | 0x%x | 0x%x | 0x%x | %d | %d | %d | %d | %d | %d | %s | %s |\n",
			row.Index,
			row.OriginOffset,
			row.ShadowOffset,
			row.OriginInstruction,
			row.ShadowInstruction,
			row.OriginPCSP,
			row.ShadowPCSP,
			row.OriginPCFile,
			row.ShadowPCFile,
			row.OriginPCLN,
			row.ShadowPCLN,
			originSrc,
			shadowSrc,
		))
	}
	return builder.String()
}

func FormatPCValueFullListCSV(rows []PCValueFullRow) string {
	var builder strings.Builder
	writer := csv.NewWriter(&builder)

	_ = writer.Write([]string{
		"idx",
		"orig_off",
		"shadow_off",
		"origin_instruction",
		"shadow_instruction",
		"origin_pcsp",
		"shadow_pcsp",
		"origin_pcfile",
		"shadow_pcfile",
		"origin_pcln",
		"shadow_pcln",
		"origin_file",
		"origin_line",
		"origin_source",
		"shadow_file",
		"shadow_line",
		"shadow_source",
	})

	for _, row := range rows {
		_ = writer.Write([]string{
			strconv.Itoa(row.Index),
			fmt.Sprintf("0x%x", row.OriginOffset),
			fmt.Sprintf("0x%x", row.ShadowOffset),
			fmt.Sprintf("0x%x", row.OriginInstruction),
			fmt.Sprintf("0x%x", row.ShadowInstruction),
			strconv.FormatInt(int64(row.OriginPCSP), 10),
			strconv.FormatInt(int64(row.ShadowPCSP), 10),
			strconv.FormatInt(int64(row.OriginPCFile), 10),
			strconv.FormatInt(int64(row.ShadowPCFile), 10),
			strconv.FormatInt(int64(row.OriginPCLN), 10),
			strconv.FormatInt(int64(row.ShadowPCLN), 10),
			row.OriginFile,
			strconv.FormatInt(int64(row.OriginLine), 10),
			row.OriginSource,
			row.ShadowFile,
			strconv.FormatInt(int64(row.ShadowLine), 10),
			row.ShadowSource,
		})
	}

	writer.Flush()
	return builder.String()
}

func buildTableDiffRows(mapping []pcMapEntry, origEntries, shadowEntries []PCDataEntry, origEntry, shadowEntry uintptr) []PCTableDiffRow {
	rows := make([]PCTableDiffRow, 0)
	seen := make(map[uint64]struct{}, len(mapping))

	for _, item := range mapping {
		origOff := uintptr(item.Orig)
		shadowOff := uintptr(item.New)

		origVal := valueAtOffset(origEntries, origOff)
		shadowVal := valueAtOffset(shadowEntries, shadowOff)
		if origVal == shadowVal {
			continue
		}

		key := (uint64(item.Orig) << 32) | uint64(item.New)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		rows = append(rows, PCTableDiffRow{
			OriginInstruction: origEntry + origOff,
			OriginValue:       origVal,
			ShadowInstruction: shadowEntry + shadowOff,
			ShadowValue:       shadowVal,
		})
	}

	return rows
}

func valueAtOffset(entries []PCDataEntry, target uintptr) int32 {
	value := int32(-1)
	for _, entry := range entries {
		if entry.Offset > target {
			break
		}
		value = entry.Value
	}
	return value
}

func formatSingleDiffTable(tableName string, rows []PCTableDiffRow) string {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("[%s]\n", tableName))
	builder.WriteString(fmt.Sprintf("| origin instruction | %s | shadow instruction | %s |\n", tableName, tableName))
	builder.WriteString(fmt.Sprintf("|---|---:|---|---:|\n"))
	if len(rows) == 0 {
		builder.WriteString("| - | - | - | - |\n")
		return builder.String()
	}
	for _, row := range rows {
		builder.WriteString(fmt.Sprintf("| 0x%x | %d | 0x%x | %d |\n", row.OriginInstruction, row.OriginValue, row.ShadowInstruction, row.ShadowValue))
	}
	return builder.String()
}

func safeFuncLine(f funcInfo, pc uintptr) (file string, line int32) {
	defer func() {
		if recover() != nil {
			file = ""
			line = 0
		}
	}()
	return funcline1(f, pc, true)
}

func readSourceLine(cache map[string][]string, file string, line int32) string {
	if file == "" || line <= 0 {
		return ""
	}

	lines, ok := cache[file]
	if !ok {
		data, err := os.ReadFile(file)
		if err != nil {
			return ""
		}
		lines = strings.Split(string(data), "\n")
		cache[file] = lines
	}

	idx := int(line) - 1
	if idx < 0 || idx >= len(lines) {
		return ""
	}
	return strings.TrimSpace(lines[idx])
}

func escapeMarkdownCell(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\t", " ")
	return s
}
