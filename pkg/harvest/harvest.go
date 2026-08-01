//go:build !go1.27

package harvest

import (
	"fmt"
	"go/constant"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/0xbu11/codebull/pkg/debugflag"
	"github.com/0xbu11/codebull/pkg/function"
	"github.com/0xbu11/codebull/pkg/instrument"
	"github.com/0xbu11/codebull/pkg/module"
	"github.com/0xbu11/codebull/pkg/ratelimit"
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
	StackTrace   []StackFrame
}

type StackFrame struct {
	FunctionName string `json:"function_name"`
	File         string `json:"file,omitempty"`
	Line         int    `json:"line,omitempty"`
	PC           uint64 `json:"pc"`
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
	rand.Seed(time.Now().UnixNano())
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

//go:nocheckptr
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

	filter := make(map[string]struct{}, len(variableNames)*2)
	for _, name := range variableNames {
		if name == "" {
			continue
		}
		filter[name] = struct{}{}
		filter["&"+name] = struct{}{}
		if strings.HasPrefix(name, "&") {
			filter[name[1:]] = struct{}{}
		}
	}
	if len(filter) == 0 {
		return nil
	}

	return filter
}

const maxStackTraceDepth = 32

func computeFrameBase(pc, sp uint64, fallback int32) (uint64, int32) {
	spDelta := fallback
	if f := variable.FindFunc(uintptr(pc)); f.Valid() {
		if delta, ok := variable.FuncSPDelta(f, uintptr(pc)); ok {
			spDelta = delta
		}
	}
	return sp + uint64(spDelta) + 8, spDelta
}

func buildStackFrame(pc uint64, callSite bool) StackFrame {
	frame := StackFrame{PC: pc, FunctionName: "unknown"}

	lookupPC := uintptr(pc)
	if callSite && lookupPC > 0 {
		lookupPC--
	}

	fnObj := runtime.FuncForPC(lookupPC)
	if fnObj == nil {
		return frame
	}

	frame.FunctionName = fnObj.Name()
	file, line := fnObj.FileLine(lookupPC)
	frame.File = file
	frame.Line = line
	return frame
}

func unwindCallerPC(bp, cfa uint64) uint64 {
	if bp != 0 {
		if pc := readMemory(uintptr(bp + 8)); pc != 0 {
			return pc
		}
	}
	if cfa < 8 {
		return 0
	}
	return readMemory(uintptr(cfa - 8))
}

func collectStackTrace(regs *OnStackRegisters) []StackFrame {
	if regs == nil || regs.PC() == 0 {
		return nil
	}

	frameBase, _ := computeFrameBase(regs.PC(), regs.SP(), 0)
	frames := make([]StackFrame, 0, 8)
	frames = append(frames, buildStackFrame(regs.PC(), false))

	bp := regs.BP()
	prevBP := bp
	callerPC := unwindCallerPC(bp, frameBase)
	callerBP := uint64(0)
	if bp != 0 {
		callerBP = readMemory(uintptr(bp))
	}

	for depth := 1; depth < maxStackTraceDepth; depth++ {
		if callerPC == 0 {
			break
		}

		frames = append(frames, buildStackFrame(callerPC, true))

		if callerBP == 0 {
			break
		}
		if prevBP != 0 && callerBP <= prevBP {
			break
		}

		nextPC := readMemory(uintptr(callerBP + 8))
		if nextPC == 0 {
			break
		}

		prevBP = callerBP
		callerPC = nextPC
		callerBP = readMemory(uintptr(callerBP))
	}

	return frames
}

func HarvestPoint(regs *OnStackRegisters) {
	pc := regs.PC()
	if !instrument.IsPointActiveAtPC(pc) {
		debugflag.Printf("Skip collect at inactive PC=0x%x", pc)
		return
	}

	if !ratelimit.Global().Allow(pc) {
		debugflag.Printf("Rate limit hit at PC=0x%x", pc)
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

	frameBase, spDelta := computeFrameBase(pc, regs.SP(), fnInfo.StackFrameSize)

	debugflag.Printf("DEBUG FRAMEBASE: PC=0x%x SP=0x%x StackFrameSize=0x%x spDelta=%d frameBase=0x%x", pc, regs.SP(), fnInfo.StackFrameSize, spDelta, frameBase)

	trace := make(map[string]uint64)

	var reportVars []VariableValue
	variableNames, hasVariableFilter := instrument.GetPointVariableNamesAtPC(pc)
	variableFilter := buildVariableFilter(variableNames)
	collectStacktrace := instrument.GetPointCollectStacktraceAtPC(pc)
	var stackTrace []StackFrame

	line, ok := instrument.GetPointLineAtPC(pc)
	if !ok {
		_, line = fnObj.FileLine(uintptr(pc))
	}
	if collectStacktrace {
		stackTrace = collectStackTrace(regs)
	}

	debugflag.Printf("Variables count: %d", len(fnInfo.Variables))
	for _, vTemplate := range fnInfo.Variables {
		debugflag.Printf("  Found DWARF variable: %s", vTemplate.Name)
		if hasVariableFilter {
			requested := false
			for req := range variableFilter {
				if req == vTemplate.Name || req == "&"+vTemplate.Name || strings.HasPrefix(req, vTemplate.Name+".") {
					requested = true
					break
				}
			}
			if !requested {
				continue
			}
		}

		v := vTemplate.Clone()

		origPC := module.GetOriginalPC(uintptr(pc))
		valAddr, err := v.Evaluate(regs, frameBase, uint64(origPC))
		if err != nil {
			v.Unreadable = fmt.Errorf("unsupported: %v", err)
			debugflag.Printf("  %s: <Error: %v>", v.Name, err)
		} else {
			v.Addr = valAddr
			v.LoadValue()
			debugflag.Printf("  %s: %v", v.Name, constantToInterface(v.Value))
		}

		if cv := toVariableValueFiltered(v, "", variableFilter, !hasVariableFilter); cv != nil {
			reportVars = append(reportVars, *cv)
		}
	}

	if hasVariableFilter {
		for reqName := range variableFilter {
			foundLocally := false
			for _, local := range fnInfo.Variables {
				if local.Name == reqName || "&"+local.Name == reqName || local.Name == "&"+reqName || strings.HasPrefix(reqName, local.Name+".") {
					foundLocally = true
					break
				}
			}

			if !foundLocally && !strings.HasPrefix(reqName, "&") {
				sampleRate := 10 // 10% chance
				if os.Getenv("EGO_SHADOW_DEBUG") == "1" {
					sampleRate = 100 // 100% chance for tests
				}
				if rand.Intn(100) < sampleRate {
					debugflag.Printf("  Attempting global variable fallback for: %s", reqName)
					if gv, err := varLocator.GetGlobalVariable(reqName); err == nil {
						valAddr, evalErr := gv.Evaluate(regs, frameBase, uint64(module.GetOriginalPC(uintptr(pc))))
						if evalErr != nil {
							if gv.Addr == 0 {
								gv.Unreadable = fmt.Errorf("global evaluate failed: %v", evalErr)
							}
						} else {
							gv.Addr = valAddr
						}

						if gv.Unreadable == nil {
							gv.LoadValue()
							debugflag.Printf("  %s (Global): %v", gv.Name, constantToInterface(gv.Value))
						}
						if cv := toVariableValueFiltered(gv, "", variableFilter, !hasVariableFilter); cv != nil {
							reportVars = append(reportVars, *cv)
						}
					} else {
						debugflag.Printf("  Global fallback failed for %s: %v", reqName, err)
					}
				} else {
					debugflag.Printf("  Global variable %s skipped due to random sampling distribution", reqName)
				}
			}
		}
	}

	TestLogMu.Lock()
	TestLog = append(TestLog, trace)
	TestReportLog = append(TestReportLog, ReportData{
		FunctionName: funcName,
		Line:         line,
		Variables:    reportVars,
		StackTrace:   stackTrace,
	})
	TestLogMu.Unlock()

	if OnReport != nil {
		data := ReportData{
			FunctionName: funcName,
			Line:         line,
			Variables:  reportVars,
			StackTrace: stackTrace,
		}
		OnReport(data)
	}
}

func byteSliceString(v *variable.Variable) (string, bool) {
	if len(v.Children) == 0 {
		return "", false
	}
	buf := make([]byte, 0, len(v.Children))
	for _, child := range v.Children {
		if child.Kind != reflect.Uint && child.Kind != reflect.Uint8 {
			return "", false
		}
		if child.Value == nil || child.Type == nil || child.Type.Common() == nil || child.Type.Common().ByteSize != 1 {
			return "", false
		}
		b, ok := constant.Uint64Val(child.Value)
		if !ok || b > 0xff {
			return "", false
		}
		buf = append(buf, byte(b))
	}
	s := string(buf)
	if !utf8.ValidString(s) {
		return "", false
	}
	if int64(len(v.Children)) < v.Len {
		s += "…"
	}
	return s, true
}

func ToVariableValue(v *variable.Variable) VariableValue {
	cv := toVariableValueFiltered(v, "", nil, true)
	if cv == nil {
		return VariableValue{} // should not happen if includeAll is true
	}
	return *cv
}

func toVariableValueFiltered(v *variable.Variable, currentPath string, filter map[string]struct{}, includeAll bool) *VariableValue {
	typeStr := "unknown"
	if v.Type != nil {
		typeStr = v.Type.String()
	}

	var nodePath string
	if currentPath == "" {
		nodePath = v.Name
	} else if v.Name == "" {
		nodePath = currentPath
	} else if strings.HasPrefix(v.Name, "[") {
		nodePath = currentPath + v.Name
	} else {
		nodePath = currentPath + "." + v.Name
	}

	nodeIncludeAll := includeAll
	if filter != nil && !nodeIncludeAll {
		if _, ok := filter[nodePath]; ok {
			nodeIncludeAll = true
		} else if _, ok := filter["&"+nodePath]; ok {
			nodeIncludeAll = true
		} else if strings.HasPrefix(nodePath, "&") {
			if _, ok := filter[nodePath[1:]]; ok {
				nodeIncludeAll = true
			}
		}
	}

	if len(v.Children) > 0 {
		childrenVals := make([]VariableValue, 0, len(v.Children))
		for _, child := range v.Children {
			childPath := nodePath
			if child.Name != "" {
				if strings.HasPrefix(child.Name, "[") {
					childPath += child.Name
				} else {
					childPath += "." + child.Name
				}
			}

			keep := nodeIncludeAll
			if !keep && filter != nil {
				for req := range filter {
					if req == childPath || strings.HasPrefix(req, childPath+".") || strings.HasPrefix(req, childPath+"[") {
						keep = true
						break
					}
					if req == "&"+childPath || strings.HasPrefix(req, "&"+childPath+".") || strings.HasPrefix(req, "&"+childPath+"[") {
						keep = true
						break
					}
				}
			}

			if keep {
				if cv := toVariableValueFiltered(child, nodePath, filter, nodeIncludeAll); cv != nil {
					childrenVals = append(childrenVals, *cv)
				}
			}
		}
		
		res := VariableValue{
			Name:     v.Name,
			Children: childrenVals,
			Type:     typeStr,
		}
		if v.Kind == reflect.Struct {
			res.Value = "{...}"
		} else if v.Kind == reflect.Interface {
			if v.Value != nil {
				res.Value = constant.StringVal(v.Value)
			}
		} else if v.Kind == reflect.Slice || v.Kind == reflect.Array {
			if s, ok := byteSliceString(v); ok {
				res.Value = s
			} else {
				res.Value = fmt.Sprintf("len=%d", v.Len)
			}
		} else if v.Kind == reflect.Ptr || v.Kind == reflect.UnsafePointer {
			if addr, ok := constant.Uint64Val(v.Value); ok {
				res.Value = fmt.Sprintf("0x%x", addr)
			}
		}
		return &res
	}

	if v.Unreadable != nil {
		return &VariableValue{
			Name:       v.Name,
			Value:      fmt.Sprintf("<Error: %v>", v.Unreadable),
			Type:       typeStr,
			Unreadable: v.Unreadable.Error(),
		}
	}

	return &VariableValue{
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
