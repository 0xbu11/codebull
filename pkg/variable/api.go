//go:build !go1.27

package variable

import (
	"debug/dwarf"
	"fmt"
	"strings"
)

type VariableQuery struct {
	FunctionName string `json:"function_name"`
	Line         int    `json:"line"`
}

type VariableDTO struct {
	Name string `json:"name"`
	Type string `json:"type"`
	ValueStr  string        `json:"value_str,omitempty"`
	HasFields bool          `json:"has_fields"`
	Fields    []VariableDTO `json:"fields,omitempty"`
}

func checkHasFields(t dwarf.Type) bool {
	if t == nil {
		return false
	}
	resolved := resolveTypedef(t)
	if pt, ok := resolved.(*dwarf.PtrType); ok {
		resolved = resolveTypedef(pt.Type)
	}
	if st, ok := resolved.(*dwarf.StructType); ok {
		dummy := &Variable{}
		if dummy.isSliceType(st) || dummy.isStringType(st) || dummy.isInterfaceType(st) {
			return false
		}
		return len(st.Field) > 0
	}
	return false
}

func BuildDTOs(vars []*Variable, path string, maxLayer int) ([]VariableDTO, error) {
	if len(vars) == 0 {
		return nil, nil
	}

	if maxLayer <= 0 {
		if path != "" {
			maxLayer = 1
		} else {
			maxLayer = 5
		}
	}

	if path == "" {
		dtos := make([]VariableDTO, 0, len(vars))
		for _, v := range vars {
			if v == nil || v.Name == "" {
				continue
			}
			dtos = append(dtos, buildDTO(v.Name, v.Type, 0, maxLayer))
		}
		return dtos, nil
	}

	parts := strings.Split(path, ".")
	var currentType dwarf.Type
	var found bool

	for _, v := range vars {
		if v != nil && v.Name == parts[0] {
			currentType = v.Type
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("variable '%s' not found", parts[0])
	}

	for i := 1; i < len(parts); i++ {
		part := parts[i]
		
		resolved := resolveTypedef(currentType)
		if pt, ok := resolved.(*dwarf.PtrType); ok {
			resolved = resolveTypedef(pt.Type)
		}

		st, ok := resolved.(*dwarf.StructType)
		if !ok {
			return nil, fmt.Errorf("cannot expand non-struct type at '%s'", strings.Join(parts[:i], "."))
		}

		dummy := &Variable{}
		if dummy.isSliceType(st) || dummy.isStringType(st) || dummy.isInterfaceType(st) {
			return nil, fmt.Errorf("cannot expand internal struct at '%s'", strings.Join(parts[:i], "."))
		}

		fieldFound := false
		for _, f := range st.Field {
			if f.Name == part {
				currentType = f.Type
				fieldFound = true
				break
			}
		}

		if !fieldFound {
			return nil, fmt.Errorf("field '%s' not found at '%s'", part, strings.Join(parts[:i], "."))
		}
	}

	resolved := resolveTypedef(currentType)
	if pt, ok := resolved.(*dwarf.PtrType); ok {
		resolved = resolveTypedef(pt.Type)
	}

	st, ok := resolved.(*dwarf.StructType)
	if !ok {
		return nil, fmt.Errorf("target path '%s' is not a struct", path)
	}

	dummy := &Variable{}
	if dummy.isSliceType(st) || dummy.isStringType(st) || dummy.isInterfaceType(st) {
		return nil, fmt.Errorf("target path '%s' is an internal struct and cannot be expanded", path)
	}

	var dtos []VariableDTO
	for _, f := range st.Field {
		dtos = append(dtos, buildDTO(f.Name, f.Type, 1, maxLayer))
	}

	return dtos, nil
}

func buildDTO(name string, t dwarf.Type, depth int, maxLayer int) VariableDTO {
	typeName := "unknown"
	if t != nil {
		typeName = t.String()
	}

	dto := VariableDTO{
		Name:      name,
		Type:      typeName,
		HasFields: checkHasFields(t),
	}

	if t == nil || depth >= maxLayer {
		return dto
	}

	resolved := resolveTypedef(t)
	
	if pt, ok := resolved.(*dwarf.PtrType); ok {
		resolved = resolveTypedef(pt.Type)
	}

	if st, ok := resolved.(*dwarf.StructType); ok {
		dummy := &Variable{}
		if dummy.isSliceType(st) || dummy.isStringType(st) || dummy.isInterfaceType(st) {
			return dto
		}

		for _, f := range st.Field {
			dto.Fields = append(dto.Fields, buildDTO(f.Name, f.Type, depth+1, maxLayer))
		}
	}

	return dto
}
