//go:build !go1.23

package variable

import (
	"debug/dwarf"
	"encoding/binary"
	"fmt"
	"go/constant"
	"go/token"
	"math"
	"reflect"
	"unsafe"

	"github.com/0xbu11/codebull/pkg/debugflag"
)

const (
	sliceArrayFieldName = "array"
	sliceLenFieldName   = "len"
	sliceCapFieldName   = "cap"
)

var MaxDepth = 10

type Variable struct {
	Name       string
	Addr       uint64
	Type       dwarf.Type
	Kind       reflect.Kind
	Value      constant.Value
	Unreadable error

	LocDescription string
	Location       []byte     // Raw DWARF location expression (if simple)
	LocList        []LocEntry // Location list entries (if location is a list)

	Children   []*Variable
	Len        int64
	Cap        int64
	Base       uint64
	stride     int64
	fieldType  dwarf.Type
	loaded     bool
	IsRegister bool
}

func (v *Variable) ResetRuntimeState() {
	v.Addr = 0
	v.Value = nil
	v.Unreadable = nil
	v.Children = nil
	v.Base = 0
	v.Len = 0
	v.Cap = 0
	v.loaded = false
	v.IsRegister = false
	if v.Type != nil {
		v.initializeType()
	}
}

func resolveTypedef(t dwarf.Type) dwarf.Type {
	for {
		tt, ok := t.(*dwarf.TypedefType)
		if !ok || tt == nil {
			return t
		}
		t = tt.Type
	}
}

type LocEntry struct {
	LowPC  uint64
	HighPC uint64
	Loc    []byte
}

func NewVariable(name string, addr uint64, typ dwarf.Type, locDesc string, location []byte) *Variable {
	v := &Variable{
		Name:           name,
		Addr:           addr,
		Type:           typ,
		LocDescription: locDesc,
		Location:       location,
	}

	if typ != nil {
		v.initializeType()
	}

	return v
}

func (v *Variable) initializeType() {
	t := resolveTypedef(v.Type)

	switch t := t.(type) {
	case *dwarf.PtrType:
		v.Kind = reflect.Ptr
		if _, isvoid := t.Type.(*dwarf.VoidType); isvoid {
			v.Kind = reflect.UnsafePointer
		}
	case *dwarf.ArrayType:
		v.Kind = reflect.Array
		v.Len = t.Count
		v.Cap = t.Count
		v.fieldType = t.Type
		if t.Count > 0 {
			v.stride = t.ByteSize / t.Count
		}
	case *dwarf.StructType:
		v.Kind = reflect.Struct


		if v.isSliceType(t) {
			v.Kind = reflect.Slice
			v.fieldType = v.resolveSliceElementType(t)
		} else if v.isStringType(t) {
			v.Kind = reflect.String
		} else if v.isInterfaceType(t) {
			v.Kind = reflect.Interface
		}

	case *dwarf.IntType:
		v.Kind = reflect.Int
	case *dwarf.UintType:
		v.Kind = reflect.Uint
	case *dwarf.FloatType:
		v.Kind = reflect.Float64
		if t.ByteSize == 4 {
			v.Kind = reflect.Float32
		}
	case *dwarf.ComplexType:
		v.Kind = reflect.Complex128
		if t.ByteSize == 8 {
			v.Kind = reflect.Complex64
		}
	case *dwarf.BoolType:
		v.Kind = reflect.Bool
	case *dwarf.UnspecifiedType:
		v.Kind = reflect.Invalid
	default:
	}
}

func (v *Variable) isSliceType(t *dwarf.StructType) bool {
	if len(t.Field) != 3 {
		return false
	}
	hasArray := false
	hasLen := false
	hasCap := false
	for _, f := range t.Field {
		if f.Name == sliceArrayFieldName {
			hasArray = true
		}
		if f.Name == sliceLenFieldName {
			hasLen = true
		}
		if f.Name == sliceCapFieldName {
			hasCap = true
		}
	}
	return hasArray && hasLen && hasCap
}

func (v *Variable) resolveSliceElementType(t *dwarf.StructType) dwarf.Type {
	for _, f := range t.Field {
		if f.Name == sliceArrayFieldName {
			if ptr, ok := f.Type.(*dwarf.PtrType); ok {
				return ptr.Type
			}
		}
	}
	return nil
}

func (v *Variable) isStringType(t *dwarf.StructType) bool {
	if len(t.Field) != 2 {
		return false
	}
	hasStr := false
	hasLen := false
	for _, f := range t.Field {
		if f.Name == "str" {
			hasStr = true
		}
		if f.Name == "len" {
			hasLen = true
		}
	}
	return hasStr && hasLen
}

func (v *Variable) isInterfaceType(t *dwarf.StructType) bool {
	if len(t.Field) != 2 {
		return false
	}
	hasType := false
	hasData := false
	for _, f := range t.Field {
		if f.Name == "tab" || f.Name == "_type" {
			hasType = true
		}
		if f.Name == "data" {
			hasData = true
		}
	}
	return hasType && hasData
}

func (v *Variable) LoadValue() {
	v.LoadValueInternal(0)
}

func (v *Variable) LoadValueInternal(depth int) {
	defer func() {
		if r := recover(); r != nil {
			v.Unreadable = fmt.Errorf("unsupported: panic while loading %q (%v)", v.Name, r)
		}
	}()

	if v.Unreadable != nil {
		return
	}
	if v.loaded {
		return
	}
	v.loaded = true

	if depth > MaxDepth {
		return
	}

	if v.IsRegister {
		v.Value = constant.MakeUint64(v.Addr)
		return
	}

	if v.Type == nil {
		v.Unreadable = fmt.Errorf("unsupported: missing DWARF type")
		return
	}

	locStr := ""
	if len(v.Location) > 0 {
		locStr = fmt.Sprintf("%x", v.Location)
	} else if len(v.LocList) > 0 {
		locStr = fmt.Sprintf("LocList[%d]", len(v.LocList))
	}

	debugflag.Printf("DEBUG EVAL: LoadValueInternal %s Kind: %v Addr: 0x%x Loc: %s", v.Name, v.Kind, v.Addr, locStr)

	switch v.Kind {
	case reflect.Ptr:
		ptrVal, err := readUintRaw(v.Addr, 8)
		if err != nil {
			v.Unreadable = err
			return
		}
		v.Value = constant.MakeUint64(ptrVal)

		ptrType, ok := resolveTypedef(v.Type).(*dwarf.PtrType)
		if !ok || ptrType == nil {
			v.Unreadable = fmt.Errorf("unsupported: expected pointer DWARF type, got %T", v.Type)
			return
		}
		targetType := ptrType.Type
		child := NewVariable("", ptrVal, targetType, "", nil)
		v.Children = []*Variable{child}

		if ptrVal != 0 {
			child.LoadValueInternal(depth + 1)
		}

	case reflect.Slice:
		if st, ok := resolveTypedef(v.Type).(*dwarf.StructType); ok {
			v.loadSliceInfo(st)
			if v.Unreadable == nil {
				v.loadArrayValues(depth)
			}
		} else {
			v.Unreadable = fmt.Errorf("unsupported: expected slice DWARF struct type, got %T", v.Type)
		}

	case reflect.Array:
		v.Base = v.Addr
		v.loadArrayValues(depth)

	case reflect.Struct:
		if st, ok := resolveTypedef(v.Type).(*dwarf.StructType); ok {
			for _, f := range st.Field {
				child, err := v.toField(f)
				if err != nil {
					continue
				}
				child.Name = f.Name
				v.Children = append(v.Children, child)
				child.LoadValueInternal(depth + 1) // Struct fields are same depth logically vs nesting? Let's inc depth.
			}
		} else {
			v.Unreadable = fmt.Errorf("unsupported: expected struct DWARF type, got %T", v.Type)
		}

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		common := v.Type.Common()
		if common == nil {
			v.Unreadable = fmt.Errorf("unsupported: missing DWARF common type")
			return
		}
		val, err := readIntRaw(v.Addr, int(common.ByteSize))
		if err != nil {
			v.Unreadable = err
			return
		}
		v.Value = constant.MakeInt64(val)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		common := v.Type.Common()
		if common == nil {
			v.Unreadable = fmt.Errorf("unsupported: missing DWARF common type")
			return
		}
		val, err := readUintRaw(v.Addr, int(common.ByteSize))
		if err != nil {
			v.Unreadable = err
			return
		}
		v.Value = constant.MakeUint64(val)

	case reflect.Bool:
		common := v.Type.Common()
		if common == nil {
			v.Unreadable = fmt.Errorf("unsupported: missing DWARF common type")
			return
		}
		val, err := readUintRaw(v.Addr, int(common.ByteSize))
		if err != nil {
			v.Unreadable = err
			return
		}
		v.Value = constant.MakeBool(val != 0)

	case reflect.Float32, reflect.Float64:
		common := v.Type.Common()
		if common == nil {
			v.Unreadable = fmt.Errorf("unsupported: missing DWARF common type")
			return
		}
		bits, err := readUintRaw(v.Addr, int(common.ByteSize))
		if err != nil {
			v.Unreadable = err
			return
		}
		if common.ByteSize == 4 {
			f := math.Float32frombits(uint32(bits))
			v.Value = constant.MakeFloat64(float64(f))
			return
		}
		f := math.Float64frombits(bits)
		v.Value = constant.MakeFloat64(f)

	case reflect.Complex64, reflect.Complex128:
		common := v.Type.Common()
		if common == nil {
			v.Unreadable = fmt.Errorf("unsupported: missing DWARF common type")
			return
		}
		byteSize := int(common.ByteSize)
		b, err := readMemory(uintptr(v.Addr), byteSize)
		if err != nil {
			v.Unreadable = err
			return
		}
		if byteSize == 8 {
			reBits := binary.LittleEndian.Uint32(b[0:4])
			imBits := binary.LittleEndian.Uint32(b[4:8])
			re := constant.MakeFloat64(float64(math.Float32frombits(reBits)))
			im := constant.MakeImag(constant.MakeFloat64(float64(math.Float32frombits(imBits))))
			v.Value = constant.BinaryOp(re, token.ADD, im)
			return
		}
		if byteSize == 16 {
			reBits := binary.LittleEndian.Uint64(b[0:8])
			imBits := binary.LittleEndian.Uint64(b[8:16])
			re := constant.MakeFloat64(math.Float64frombits(reBits))
			im := constant.MakeImag(constant.MakeFloat64(math.Float64frombits(imBits)))
			v.Value = constant.BinaryOp(re, token.ADD, im)
			return
		}
		v.Unreadable = fmt.Errorf("unsupported: unexpected complex byte size %d", byteSize)

	case reflect.String:
		if st, ok := resolveTypedef(v.Type).(*dwarf.StructType); ok {
			var lenVal int64
			for _, f := range st.Field {
				if f.Name == "len" {
					lenVar, _ := v.toField(f)
					lenVar.LoadValueInternal(depth + 1)
					lenVal, _ = constant.Int64Val(lenVar.Value)
				}
			}
			v.Len = lenVal

			for _, f := range st.Field {
				if f.Name == "str" {
					strPtrVar, _ := v.toField(f)
					strPtrVar.LoadValueInternal(depth + 1)
					ptrVal, _ := constant.Uint64Val(strPtrVar.Value)

					if ptrVal != 0 && lenVal > 0 {
						if lenVal > 1024 {
							lenVal = 1024
						} // Cap string read
						b, err := readMemory(uintptr(ptrVal), int(lenVal))
						if err == nil {
							v.Value = constant.MakeString(string(b))
						}
					}
				}
			}
		}
	}
}

func (v *Variable) loadSliceInfo(t *dwarf.StructType) {
	for _, f := range t.Field {
		switch f.Name {
		case sliceArrayFieldName:
			ptrVar, err := v.toField(f)
			if err == nil {
				base, err := readUintRaw(ptrVar.Addr, 8) // Valid for 64-bit
				if err == nil {
					v.Base = base
				}
				if ptrType, ok := f.Type.(*dwarf.PtrType); ok {
					v.fieldType = ptrType.Type
					v.stride = v.fieldType.Common().ByteSize
				}
			}
		case sliceLenFieldName:
			lstrAddr, _ := v.toField(f)
			lval, err := readIntRaw(lstrAddr.Addr, 8)
			if err == nil {
				v.Len = lval
			}
		case sliceCapFieldName:
			cstrAddr, _ := v.toField(f)
			cval, err := readIntRaw(cstrAddr.Addr, 8)
			if err == nil {
				v.Cap = cval
			}
		}
	}
}

func (v *Variable) loadArrayValues(depth int) {
	if v.Unreadable != nil || v.Len == 0 || v.Base == 0 {
		return
	}

	count := v.Len
	if count > 100 {
		count = 100
	} // Cap array display

	for i := int64(0); i < count; i++ {
		offset := uint64(i * v.stride)
		elemAddr := v.Base + offset
		child := NewVariable(fmt.Sprintf("[%d]", i), elemAddr, v.fieldType, "", nil)
		v.Children = append(v.Children, child)
		child.LoadValueInternal(depth + 1)
	}
}

func (v *Variable) toField(field *dwarf.StructField) (*Variable, error) {
	return NewVariable(field.Name, uint64(int64(v.Addr)+field.ByteOffset), field.Type, "", nil), nil
}


func readMemory(addr uintptr, size int) (buf []byte, err error) {
	if size <= 0 {
		return nil, fmt.Errorf("readMemory invalid size %d", size)
	}


	buf = make([]byte, size)

	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic reading memory at 0x%x: %v", addr, r)
			buf = nil
		}
	}()

	for i := 0; i < size; i++ {
		ptr := unsafe.Pointer(addr + uintptr(i))
		buf[i] = *(*byte)(ptr)
	}
	return buf, nil
}

func readUintRaw(addr uint64, size int) (uint64, error) {
	b, err := readMemory(uintptr(addr), size)
	if err != nil {
		return 0, err
	}

	switch size {
	case 1:
		return uint64(b[0]), nil
	case 2:
		return uint64(binary.LittleEndian.Uint16(b)), nil
	case 4:
		return uint64(binary.LittleEndian.Uint32(b)), nil
	case 8:
		return binary.LittleEndian.Uint64(b), nil
	}
	return 0, fmt.Errorf("unsupported size %d", size)
}

func readIntRaw(addr uint64, size int) (int64, error) {
	u, err := readUintRaw(addr, size)
	if err != nil {
		return 0, err
	}

	switch size {
	case 1:
		return int64(int8(u)), nil
	case 2:
		return int64(int16(u)), nil
	case 4:
		return int64(int32(u)), nil
	case 8:
		return int64(u), nil
	}
	return 0, fmt.Errorf("unsupported size %d", size)
}
