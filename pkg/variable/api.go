//go:build !go1.27

package variable

import (
	"debug/dwarf"
)

type VariableQuery struct {
	FunctionName string `json:"function_name"`
	Line         int    `json:"line"`
}

type VariableDTO struct {
	Name string `json:"name"`
	Type string `json:"type"`
	ValueStr string        `json:"value_str,omitempty"`
	Fields   []VariableDTO `json:"fields,omitempty"`
}

func BuildDTOs(vars []*Variable) []VariableDTO {
	if len(vars) == 0 {
		return nil
	}

	dtos := make([]VariableDTO, 0, len(vars))
	for _, v := range vars {
		if v == nil || v.Name == "" {
			continue
		}
		dtos = append(dtos, buildDTO(v.Name, v.Type, 0))
	}
	return dtos
}

func buildDTO(name string, t dwarf.Type, depth int) VariableDTO {
	typeName := "unknown"
	if t != nil {
		typeName = t.String()
	}

	dto := VariableDTO{
		Name: name,
		Type: typeName,
	}

	if t == nil || depth > 5 {
		return dto
	}

	resolved := resolveTypedef(t)
	
	if pt, ok := resolved.(*dwarf.PtrType); ok {
		resolved = resolveTypedef(pt.Type)
	}

	if st, ok := resolved.(*dwarf.StructType); ok {
		var dummy *Variable
		if dummy.isSliceType(st) || dummy.isStringType(st) || dummy.isInterfaceType(st) {
			return dto
		}

		for _, f := range st.Field {
			dto.Fields = append(dto.Fields, buildDTO(f.Name, f.Type, depth+1))
		}
	}

	return dto
}
