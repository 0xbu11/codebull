//go:build !go1.23

package harvest

import (
	"fmt"
	"go/constant"
	"runtime"
	"strconv"
	"sync"
	"unsafe"

	"github.com/0xbu11/codebull/pkg/debugflag"
	"github.com/0xbu11/codebull/pkg/function"
	"github.com/0xbu11/codebull/pkg/instrument"
	"github.com/0xbu11/codebull/pkg/variable"
)

var (
	loadOnce    sync.Once
	varLocator  *function.Locator
	binaryError error

	TestLog   []map[string]uint64
	TestLogMu sync.Mutex

	TestReportLog []ReportData
)

type ReportData struct {
	FunctionName string
	Line         int
	Timestamp    string
	Variables    []VariableValue
}

type VariableValue struct {
	Name       string          `json:"name"`
	Value      string          `json:"value"`
	Type       string          `json:"type"`
	Children   []VariableValue `json:"children,omitempty"`
	Unreadable string          `json:"unreadable,omitempty"`
}

var OnReport func(ReportData)

func SetOnReport(fn func(ReportData)) {
	OnReport = fn
}

func init() {
	loadOnce.Do(initLocator)
}

func initLocator() {
	var err error
	varLocator, err = function.NewLocatorForSelf()
	if err != nil {
		binaryError = err
	}
}

type OnStackRegisters struct {
	RAX       uint64
	RCX       uint64
	RDX       uint64
	RBX       uint64
	RSP_Dummy uint64
	RBP       uint64 // Encoded RBP (Current Trampoline Frame Ptr)
	RSI       uint64
	RDI       uint64
	R8        uint64
	R9        uint64
	R10       uint64
	R11_Bad   uint64 // This R11 holds RIP garbage from push
	R12       uint64
	R13       uint64
	R14       uint64
	R15       uint64
	RFLAGS    uint64
	RIP       uint64
	SavedR11  uint64 // The Real R11 value
	OldRBP    uint64
}

func (r *OnStackRegisters) Get(reg uint64) (uint64, error) {
	switch reg {
	case 0:
		return r.RAX, nil
	case 1:
		return r.RDX, nil
	case 2:
		return r.RCX, nil
	case 3:
		return r.RBX, nil
	case 4:
		return r.RSI, nil
	case 5:
		return r.RDI, nil
	case 6:
		return r.OldRBP, nil
	case 7:
		return r.RSP_Dummy, nil
	case 8:
		return r.R8, nil
	case 9:
		return r.R9, nil
	case 10:
		return r.R10, nil
	case 11:
		return r.SavedR11, nil
	case 12:
		return r.R12, nil
	case 13:
		return r.R13, nil
	case 14:
		return r.R14, nil
	case 15:
		return r.R15, nil
	case 16:
		return r.RIP, nil
	case 49:
		return r.RFLAGS, nil
	default:
		return 0, fmt.Errorf("unsupported register %d", reg)
	}
}

func (r *OnStackRegisters) PC() uint64 {
	return r.RIP
}

func (r *OnStackRegisters) SP() uint64 {
	val, _ := r.Get(7)
	return val
}

func (r *OnStackRegisters) BP() uint64 {
	val, _ := r.Get(6)
	return val
}

func readMemory(addr uintptr) uint64 {
	defer func() {
		if r := recover(); r != nil {
		}
	}()
	if addr == 0 {
		return 0
	}
	return *(*uint64)(unsafe.Pointer(addr))
}

func buildVariableFilter(variableNames []string) map[string]struct{} {
	if len(variableNames) == 0 {
		return nil
	}

	filter := make(map[string]struct{}, len(variableNames))
	for _, name := range variableNames {
		if name == "" {
			continue
		}
		filter[name] = struct{}{}
	}
	if len(filter) == 0 {
		return nil
	}

	return filter
}

func HarvestPoint(regs *OnStackRegisters) {
	pc := regs.PC()
	if !instrument.IsPointActiveAtPC(pc) {
		debugflag.Printf("Skip collect at inactive PC=0x%x", pc)
		return
	}

	if debugflag.Enabled() {
		debugflag.Printf("DEBUG REGS: PC=0x%x SP=0x%x RAX=0x%x RBP=0x%x OldRBP=0x%x", pc, regs.SP(), regs.RAX, regs.BP(), regs.OldRBP)
		debugflag.Println("STACK DUMP FROM SP:")
		sp := regs.SP()
		for i := -2; i < 30; i++ {
			addr := sp + uint64(i*8)
			val := *(*uint64)(unsafe.Pointer(uintptr(addr)))
			if val == regs.RAX || val == 1000000000 {
				debugflag.Printf("  *[SP+%3d] 0x%x = %d (MATCH!)", i*8, addr, val)
			} else {
				debugflag.Printf("   [SP+%3d] 0x%x = %d", i*8, addr, val)
			}
		}
	}

	loadOnce.Do(initLocator)
	if binaryError != nil {
		debugflag.Printf("Instrumentation Error: %v", binaryError)
		return
	}

	debugflag.Printf("CollectBreakpoint: PC=0x%x", pc)
	fnObj := runtime.FuncForPC(uintptr(pc))
	if fnObj == nil {
		debugflag.Println("Unknown function")
		return
	}
	funcName := fnObj.Name()

	fnInfo, err := varLocator.GetFunction(funcName)
	if err != nil {
		debugflag.Printf("DWARF Info not found for %s: %v", funcName, err)
		return
	}

	debugflag.Println("Variables:")

	spDelta := int32(0)
	spDeltaOK := false
	if f := variable.FindFunc(uintptr(pc)); f.Valid() {
		if delta, ok := variable.FuncSPDelta(f, uintptr(pc)); ok {
			spDelta = delta
			spDeltaOK = true
		}
	}

	frameBase := regs.SP() + uint64(spDelta) + 8




	if !spDeltaOK {
		spDelta = int32(fnInfo.StackFrameSize)
		frameBase = regs.SP() + uint64(spDelta) + 8
	}



	debugflag.Printf("DEBUG FRAMEBASE: PC=0x%x SP=0x%x StackFrameSize=0x%x spDelta=%d frameBase=0x%x", pc, regs.SP(), fnInfo.StackFrameSize, spDelta, frameBase)

	trace := make(map[string]uint64)

	var reportVars []VariableValue
	variableNames, hasVariableFilter := instrument.GetPointVariableNamesAtPC(pc)
	variableFilter := buildVariableFilter(variableNames)

	line, ok := instrument.GetPointLineAtPC(pc)
	if !ok {
		_, line = fnObj.FileLine(uintptr(pc))
	}

	for _, v := range fnInfo.Variables {
		if hasVariableFilter {
			if _, ok := variableFilter[v.Name]; !ok {
				continue
			}
		}

		v.ResetRuntimeState()

		valAddr, err := v.Evaluate(regs, frameBase, regs.PC())
		if err != nil {
			v.Unreadable = fmt.Errorf("unsupported: %v", err)
		} else {
			v.Addr = valAddr
			v.LoadValue()
		}


		reportVars = append(reportVars, toVariableValue(v))
	}

	TestLogMu.Lock()
	TestLog = append(TestLog, trace)
	TestReportLog = append(TestReportLog, ReportData{
		FunctionName: funcName,
		Line:         line,
		Variables:    reportVars,
	})
	TestLogMu.Unlock()

	if OnReport != nil {
		data := ReportData{
			FunctionName: funcName,
			Line:         line,
			Variables: reportVars,
		}
		OnReport(data)
	}
}

func toVariableValue(v *variable.Variable) VariableValue {
	typeStr := "unknown"
	if v.Type != nil {
		typeStr = v.Type.String()
	}

	if len(v.Children) > 0 {
		childrenVals := make([]VariableValue, len(v.Children))
		for i, child := range v.Children {
			childrenVals[i] = toVariableValue(child)
		}
		return VariableValue{
			Name:     v.Name,
			Children: childrenVals,
			Type:     typeStr,
		}
	}

	if v.Unreadable != nil {
		return VariableValue{
			Name:       v.Name,
			Value:      fmt.Sprintf("<Error: %v>", v.Unreadable),
			Type:       typeStr,
			Unreadable: v.Unreadable.Error(),
		}
	}

	return VariableValue{
		Name:  v.Name,
		Value: fmt.Sprintf("%v", constantToInterface(v.Value)),
		Type:  typeStr,
	}
}

func constantToInterface(val interface{}) interface{} {
	if val == nil {
		return nil
	}
	cv, ok := val.(constant.Value)
	if !ok {
		return fmt.Sprintf("%v", val)
	}

	switch cv.Kind() {
	case constant.Bool:
		return strconv.FormatBool(constant.BoolVal(cv))
	case constant.Int:
		if i, ok := constant.Int64Val(cv); ok {
			return strconv.FormatInt(i, 10)
		}
		return cv.String()
	case constant.Float:
		if f, ok := constant.Float64Val(cv); ok {
			return strconv.FormatFloat(f, 'g', -1, 64)
		}
		return cv.String()
	case constant.Complex:
		re, _ := constant.Float64Val(constant.Real(cv))
		im, _ := constant.Float64Val(constant.Imag(cv))
		sign := "+"
		if im < 0 {
			sign = "-"
			im = -im
		}
		return "(" + strconv.FormatFloat(re, 'g', -1, 64) + sign + strconv.FormatFloat(im, 'g', -1, 64) + "i)"
	case constant.String:
		return constant.StringVal(cv)
	default:
		return cv.String()
	}
}
