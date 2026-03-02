//go:build !go1.23

package instrument

import (
	"debug/elf"
	"fmt"
	"os"
	"runtime"
	"sync"
	"unsafe"

	"github.com/0xbu11/codebull/pkg/function"
	"github.com/0xbu11/codebull/pkg/guard"
	"github.com/0xbu11/codebull/pkg/module"
	"github.com/0xbu11/codebull/pkg/codebull"
	"github.com/0xbu11/codebull/pkg/suspension"
	"github.com/0xbu11/codebull/pkg/variable"
	"golang.org/x/arch/x86/x86asm"
)

type InstrumentType int

const (
	Logging InstrumentType = iota
	Metric
	Profiling
)

func (t InstrumentType) String() string {
	switch t {
	case Logging:
		return "Logging"
	case Metric:
		return "Metric"
	case Profiling:
		return "Profiling"
	default:
		return "Unknown"
	}
}

func hasSelfRecursiveCall(fn *function.Function) bool {
	if fn == nil || fn.End <= fn.Entry {
		return false
	}

	sz := int(fn.End - fn.Entry)
	code := (*[1 << 30]byte)(unsafe.Pointer(uintptr(fn.Entry)))[:sz:sz]
	for off := uint64(0); off < uint64(len(code)); {
		inst, err := x86asm.Decode(code[int(off):], 64)
		if err != nil || inst.Len <= 0 {
			off++
			continue
		}

		instBytes := code[int(off) : int(off)+inst.Len]
		if len(instBytes) >= 5 && instBytes[0] == 0xE8 {
			rel := int32(instBytes[1]) | int32(instBytes[2])<<8 | int32(instBytes[3])<<16 | int32(instBytes[4])<<24
			target := uintptr(fn.Entry+off) + uintptr(inst.Len) + uintptr(int64(rel))
			if target >= uintptr(fn.Entry) && target < uintptr(fn.End) {
				if rf := runtime.FuncForPC(target); rf != nil && rf.Name() == fn.Name {
					return true
				}
			}
		}

		off += uint64(inst.Len)
	}

	return false
}

func allowRecursiveInstrumentation() bool {
	v := os.Getenv("EGO_SHADOW_ALLOW_RECURSIVE")
	return v == "1" || v == "true" || v == "TRUE"
}

type PointStatus int

const (
	PointActive PointStatus = iota
	PointSoftDeleted
	PointHardDeleted
)

func (s PointStatus) String() string {
	switch s {
	case PointActive:
		return "active"
	case PointSoftDeleted:
		return "soft_deleted"
	case PointHardDeleted:
		return "hard_deleted"
	default:
		return "unknown"
	}
}

type Point struct {
	File     string
	Function *function.Function
	Line     int
	Address  uint64
	Types    []InstrumentType
	Status   PointStatus
}

type Manager struct {
	mu sync.RWMutex
	points map[string][]Point
	functions map[string]*function.Function
	locator *function.Locator
	originalBytes map[string][]byte
	CollectorAddr uint64
}

var (
	pcStatusMu    sync.RWMutex
	pointStatusBy = make(map[uint64]PointStatus)
	pointLineBy   = make(map[uint64]int)
)

func NewManager() (*Manager, error) {
	m := &Manager{
		points:        make(map[string][]Point),
		functions:     make(map[string]*function.Function),
		originalBytes: make(map[string][]byte),
	}

	dwarfData, err := variable.LoadSelfDWARF()
	if err != nil {
		return m, fmt.Errorf("failed to load DWARF: %w", err)
	}

	reader, err := variable.NewBinaryReader()
	if err != nil {
		return m, fmt.Errorf("failed to create binary reader: %w", err)
	}

	var debugLoc []byte
	if exePath, err := os.Executable(); err == nil {
		if f, err := elf.Open(exePath); err == nil {
			if sec := f.Section(".debug_loc"); sec != nil {
				debugLoc, _ = sec.Data()
			}
			f.Close()
		}
	}

	m.locator = function.NewLocator(dwarfData, reader, debugLoc)
	return m, nil
}

func key(function string) string {
	return function
}

func hasPointByLine(points []Point, line int) bool {
	for _, point := range points {
		if point.Line == line && point.Status == PointActive {
			return true
		}
	}
	return false
}

func hasPointByAddress(points []Point, addr uint64) bool {
	for _, point := range points {
		if point.Address == addr && point.Status == PointActive {
			return true
		}
	}
	return false
}

func collectActivePoints(points []Point) []Point {
	active := make([]Point, 0, len(points))
	for _, point := range points {
		if point.Status == PointActive {
			active = append(active, point)
		}
	}
	return active
}

func statusPriority(status PointStatus) int {
	switch status {
	case PointActive:
		return 3
	case PointSoftDeleted:
		return 2
	case PointHardDeleted:
		return 1
	default:
		return 0
	}
}

func setPCStatus(pc uint64, status PointStatus, line int) {
	pcStatusMu.Lock()
	defer pcStatusMu.Unlock()
	pointStatusBy[pc] = status
	if line > 0 {
		pointLineBy[pc] = line
	} else {
		delete(pointLineBy, pc)
	}
}

func removePCStatus(pc uint64) {
	pcStatusMu.Lock()
	defer pcStatusMu.Unlock()
	delete(pointStatusBy, pc)
	delete(pointLineBy, pc)
}

func IsPointActiveAtPC(pc uint64) bool {
	pcStatusMu.RLock()
	defer pcStatusMu.RUnlock()
	status, ok := pointStatusBy[pc]
	return ok && status == PointActive
}

func GetPointLineAtPC(pc uint64) (int, bool) {
	pcStatusMu.RLock()
	defer pcStatusMu.RUnlock()

	status, ok := pointStatusBy[pc]
	if !ok || status != PointActive {
		return 0, false
	}

	line, ok := pointLineBy[pc]
	if !ok || line <= 0 {
		return 0, false
	}

	return line, true
}

func (m *Manager) refreshPCStatusByAddressLocked(addr uint64) {
	found := false
	best := PointHardDeleted
	bestLine := 0

	for _, points := range m.points {
		for _, point := range points {
			if point.Address != addr {
				continue
			}
			if !found || statusPriority(point.Status) > statusPriority(best) {
				best = point.Status
				bestLine = point.Line
				found = true
			}
		}
	}

	if !found {
		removePCStatus(addr)
		return
	}

	setPCStatus(addr, best, bestLine)
}

func (m *Manager) RegisterFunction(fn *function.Function) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if fn == nil {
		return fmt.Errorf("function cannot be nil")
	}
	if fn.Name == "" {
		return fmt.Errorf("function name is required")
	}

	m.functions[fn.Name] = fn
	return nil
}

func (m *Manager) GetFunction(functionName string) (*function.Function, error) {
	m.mu.RLock()
	fn, ok := m.functions[functionName]
	m.mu.RUnlock()
	if ok {
		return fn, nil
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if fn, ok = m.functions[functionName]; ok {
		return fn, nil
	}

	if m.locator == nil {
		return nil, fmt.Errorf("locator not initialized")
	}

	var err error
	fn, err = m.locator.GetFunction(functionName)
	if err != nil {
		return nil, err
	}
	m.functions[functionName] = fn
	return fn, nil
}

func (m *Manager) SetCollectorAddr(addr uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.CollectorAddr = addr
}


func (m *Manager) CreatePoint(fileName, functionName string, line int, types []InstrumentType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if functionName == "" {
		return fmt.Errorf("function name is required")
	}

	var fn *function.Function
	var ok bool

	if fn, ok = m.functions[functionName]; !ok {
		if m.locator == nil {
			return fmt.Errorf("locator not initialized, cannot look up function %s", functionName)
		}
		var err error
		fn, err = m.locator.GetFunction(functionName)
		if err != nil {
			return fmt.Errorf("function %s not found in DWARF: %w", functionName, err)
		}
		m.functions[functionName] = fn
	}

	if hasSelfRecursiveCall(fn) && !allowRecursiveInstrumentation() {
		return fmt.Errorf("function %s is recursive and blocked by default; set EGO_SHADOW_ALLOW_RECURSIVE=1 to override", functionName)
	}

	if m.locator == nil {
		return fmt.Errorf("locator required for line resolution")
	}
	addr, err := m.resolveSafeLineAddress(fn, functionName, line)
	if err != nil {
		return fmt.Errorf("failed to resolve address for line %d in %s: %w", line, functionName, err)
	}

	p := Point{
		File:     fileName,
		Function: fn,
		Line:     line,
		Address:  addr,
		Types:    types,
		Status:   PointActive,
	}

	k := key(fn.Name)
	if hasPointByLine(m.points[k], line) {
		setPCStatus(addr, PointActive, line)
		return nil
	}
	for i := range m.points[k] {
		if m.points[k][i].Line == line && m.points[k][i].Status == PointSoftDeleted {
			candidate := make([]Point, len(m.points[k]))
			copy(candidate, m.points[k])
			candidate[i] = p
			if err := m.updateShadowFunction(fn, collectActivePoints(candidate)); err != nil {
				return err
			}
			m.points[k] = candidate
			setPCStatus(addr, PointActive, line)
			return nil
		}
	}
	candidate := append([]Point(nil), m.points[k]...)
	candidate = append(candidate, p)
	if err := m.updateShadowFunction(fn, collectActivePoints(candidate)); err != nil {
		return err
	}
	m.points[k] = candidate
	setPCStatus(addr, PointActive, line)
	return nil
}

func (m *Manager) resolveSafeLineAddress(fn *function.Function, functionName string, line int) (uint64, error) {
	if m.locator == nil {
		return 0, fmt.Errorf("locator required for line resolution")
	}

	return m.locator.GetLineAddress(functionName, line)
}

func (m *Manager) CreatePointAtAddress(functionName string, addr uint64, types []InstrumentType) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if functionName == "" {
		return fmt.Errorf("function name is required")
	}

	var fn *function.Function
	var ok bool

	if fn, ok = m.functions[functionName]; !ok {
		if m.locator != nil {
			var err error
			fn, err = m.locator.GetFunction(functionName)
			if err == nil {
				m.functions[functionName] = fn
			}
		}
	}

	if fn == nil {
		return fmt.Errorf("function %s not found (must be registered or in DWARF)", functionName)
	}

	if hasSelfRecursiveCall(fn) && !allowRecursiveInstrumentation() {
		return fmt.Errorf("function %s is recursive and blocked by default; set EGO_SHADOW_ALLOW_RECURSIVE=1 to override", functionName)
	}

	if addr < fn.Entry || addr >= fn.End {
		return fmt.Errorf("address 0x%x is outside function %s [0x%x, 0x%x)", addr, functionName, fn.Entry, fn.End)
	}

	p := Point{
		File:     "unknown",
		Function: fn,
		Line:     0, // Unknown
		Address:  addr,
		Types:    types,
		Status:   PointActive,
	}

	k := key(fn.Name)
	if hasPointByAddress(m.points[k], addr) {
		setPCStatus(addr, PointActive, 0)
		return nil
	}
	for i := range m.points[k] {
		if m.points[k][i].Address == addr && m.points[k][i].Status == PointSoftDeleted {
			candidate := make([]Point, len(m.points[k]))
			copy(candidate, m.points[k])
			candidate[i] = p
			if err := m.updateShadowFunction(fn, collectActivePoints(candidate)); err != nil {
				return err
			}
			m.points[k] = candidate
			setPCStatus(addr, PointActive, 0)
			return nil
		}
	}
	candidate := append([]Point(nil), m.points[k]...)
	candidate = append(candidate, p)
	if err := m.updateShadowFunction(fn, collectActivePoints(candidate)); err != nil {
		return err
	}
	m.points[k] = candidate
	setPCStatus(addr, PointActive, 0)
	return nil
}

func (m *Manager) updateShadowFunction(fn *function.Function, points []Point) error {
	var collectAddrs []uint64
	for _, p := range points {
		collectAddrs = append(collectAddrs, p.Address)
	}

	k := key(fn.Name)
	origBytes, ok := m.originalBytes[k]
	if !ok {
		sz := fn.End - fn.Entry
		if sz == 0 {
			return fmt.Errorf("function size is 0")
		}
		src := (*[1 << 30]byte)(unsafe.Pointer(uintptr(fn.Entry)))[:sz:sz]
		origBytes = make([]byte, sz)
		copy(origBytes, src)
		m.originalBytes[k] = origBytes
	}

	newBytes, newAddr, prologueShift, err := codebull.CreateShadowFunctionFromBytes(fn.Entry, fn.End, origBytes, collectAddrs, m.CollectorAddr)
	if err != nil {
		return fmt.Errorf("failed to copy function: %w", err)
	}

	if err := module.PatchModule(fn.Entry, newAddr, newAddr+uint64(len(newBytes)), prologueShift); err != nil {
		return fmt.Errorf("failed to patch module: %w", err)
	}

	suspension.StopTheWorld("enable shadow function")
	defer suspension.StartTheWorld()

	if err := guard.Check(fn.Entry, fn.End); err != nil {
		return fmt.Errorf("failed to enable shadow function: %w", err)
	}

	if err := codebull.EnableShadowFunction(fn.Entry, newAddr); err != nil {
		return fmt.Errorf("failed to enable shadow function: %w", err)
	}

	return nil
}

func (m *Manager) RemovePoint(fileName string, line int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	found := false
	affected := make(map[uint64]struct{})
	for i := range m.points {
		for j := range m.points[i] {
			if m.points[i][j].File == fileName && m.points[i][j].Line == line && m.points[i][j].Status == PointActive {
				found = true
				m.points[i][j].Status = PointSoftDeleted
				affected[m.points[i][j].Address] = struct{}{}
			}
		}
	}

	if !found {
		return fmt.Errorf("point not found at %s:%d", fileName, line)
	}

	for addr := range affected {
		m.refreshPCStatusByAddressLocked(addr)
	}

	return nil
}

func (m *Manager) RemovePointByAddress(functionName string, addr uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	points, ok := m.points[functionName]
	if !ok {
		return fmt.Errorf("function %s not instrumented", functionName)
	}

	found := false
	for i := range points {
		if points[i].Address == addr && points[i].Status == PointActive {
			found = true
			points[i].Status = PointSoftDeleted
		}
	}

	if !found {
		return fmt.Errorf("point not found in %s at address 0x%x", functionName, addr)
	}

	m.refreshPCStatusByAddressLocked(addr)

	return nil
}

func (m *Manager) RemovePointByFunction(functionName string, line int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	points, ok := m.points[functionName]
	if !ok {
		return fmt.Errorf("function %s not instrumented", functionName)
	}

	found := false
	affected := make(map[uint64]struct{})
	for i := range points {
		if points[i].Line == line && points[i].Status == PointActive {
			found = true
			points[i].Status = PointSoftDeleted
			affected[points[i].Address] = struct{}{}
		}
	}

	if !found {
		return fmt.Errorf("point not found in %s at line %d", functionName, line)
	}

	for addr := range affected {
		m.refreshPCStatusByAddressLocked(addr)
	}

	return nil
}

func (m *Manager) GetPoints(function string) []Point {
	m.mu.RLock()
	defer m.mu.RUnlock()
	k := key(function)
	points := collectActivePoints(m.points[k])
	result := make([]Point, len(points))
	copy(result, points)
	return result
}
