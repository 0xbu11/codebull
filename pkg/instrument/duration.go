//go:build !go1.27

package instrument

import (
	"fmt"

	"github.com/0xbu11/codebull/pkg/duration"
	"github.com/0xbu11/codebull/pkg/function"
	"github.com/0xbu11/codebull/pkg/ratelimit"
)

func (m *Manager) CreateDurationPoint(fileName, functionName string, line, endLine int, ratelimitCfg *ratelimit.Config) error {
	if isBlacklisted(functionName) {
		return fmt.Errorf("function %s is blacklisted for instrumentation (unsafe runtime function)", functionName)
	}
	if line <= 0 || endLine <= 0 || line == endLine {
		return fmt.Errorf("duration requires two distinct lines, got line=%d end_line=%d", line, endLine)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	fn, err := m.lookupFunctionLocked(functionName)
	if err != nil {
		return err
	}
	if m.locator == nil {
		return fmt.Errorf("locator required for line resolution")
	}
	entryAddr, err := m.resolveSafeLineAddress(fn, functionName, line)
	if err != nil {
		return fmt.Errorf("failed to resolve address for line %d in %s: %w", line, functionName, err)
	}
	exitAddr, err := m.resolveSafeLineAddress(fn, functionName, endLine)
	if err != nil {
		return fmt.Errorf("failed to resolve address for end_line %d in %s: %w", endLine, functionName, err)
	}

	return m.createDurationPointLocked(fileName, fn, entryAddr, exitAddr, line, endLine, ratelimitCfg)
}

func (m *Manager) CreateDurationPointAtAddress(functionName string, entryAddr, exitAddr uint64, entryLine, endLine int, ratelimitCfg *ratelimit.Config) error {
	if isBlacklisted(functionName) {
		return fmt.Errorf("function %s is blacklisted for instrumentation (unsafe runtime function)", functionName)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	fn, err := m.lookupFunctionLocked(functionName)
	if err != nil {
		return err
	}
	for _, addr := range []uint64{entryAddr, exitAddr} {
		if addr < fn.Entry || addr >= fn.End {
			return fmt.Errorf("address 0x%x is outside function %s [0x%x, 0x%x)", addr, functionName, fn.Entry, fn.End)
		}
	}

	return m.createDurationPointLocked("unknown", fn, entryAddr, exitAddr, entryLine, endLine, ratelimitCfg)
}

func (m *Manager) lookupFunctionLocked(functionName string) (*function.Function, error) {
	if functionName == "" {
		return nil, fmt.Errorf("function name is required")
	}
	fn, ok := m.functions[functionName]
	if !ok {
		if m.locator == nil {
			return nil, fmt.Errorf("function %s not found (must be registered or in DWARF)", functionName)
		}
		var err error
		fn, err = m.locator.GetFunction(functionName)
		if err != nil {
			return nil, fmt.Errorf("function %s not found in DWARF: %w", functionName, err)
		}
		m.functions[functionName] = fn
	}
	if hasSelfRecursiveCall(fn) && !allowRecursiveInstrumentation() {
		return nil, fmt.Errorf("function %s is recursive and blocked by default; set EGO_SHADOW_ALLOW_RECURSIVE=1 to override", functionName)
	}
	return fn, nil
}

func (m *Manager) createDurationPointLocked(fileName string, fn *function.Function, entryAddr, exitAddr uint64, entryLine, endLine int, ratelimitCfg *ratelimit.Config) error {
	if entryAddr == exitAddr {
		return fmt.Errorf("entry and end lines resolve to the same address 0x%x; the section is empty", entryAddr)
	}
	for _, addr := range []uint64{entryAddr, exitAddr} {
		if IsPointActiveAtPC(addr) {
			return fmt.Errorf("address 0x%x already has an active log point; remove it before adding a duration point", addr)
		}
		if meta, ok := duration.LookupPC(addr); ok {
			return fmt.Errorf("address 0x%x already belongs to duration pair %d", addr, meta.PairID)
		}
	}

	pairID, err := duration.Register(fn.Name, entryAddr, exitAddr, entryLine, endLine)
	if err != nil {
		return err
	}

	k := key(fn.Name)
	entry := Point{
		File:     fileName,
		Function: fn,
		Line:     entryLine,
		Address:  entryAddr,
		Types:    []InstrumentType{Duration},
		Status:   PointActive,
		PairID:   pairID,
	}
	exit := entry
	exit.Line = endLine
	exit.Address = exitAddr
	exit.RateLimit = ratelimitCfg

	candidate := append([]Point(nil), m.points[k]...)
	candidate = append(candidate, entry, exit)
	if err := m.updateShadowFunction(fn, collectActivePoints(candidate)); err != nil {
		_ = duration.Unregister(pairID)
		return err
	}
	m.points[k] = candidate

	if ratelimitCfg != nil {
		ratelimit.Global().Register(exitAddr, *ratelimitCfg)
	}
	return nil
}

func (m *Manager) RemoveDurationPoint(functionName string, line, endLine int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	points, ok := m.points[functionName]
	if !ok {
		return fmt.Errorf("function %s not instrumented", functionName)
	}

	var pairID uint64
	for i := range points {
		if points[i].PairID != 0 && points[i].Status == PointActive &&
			points[i].Line == line && hasDurationType(points[i].Types) {
			pairID = points[i].PairID
			break
		}
	}
	if pairID == 0 {
		return fmt.Errorf("duration point not found in %s at line %d", functionName, line)
	}

	for i := range points {
		if points[i].PairID == pairID && points[i].Status == PointActive {
			if points[i].Line != line && points[i].Line != endLine {
				return fmt.Errorf("duration pair %d in %s covers lines %d-%d, not %d-%d",
					pairID, functionName, line, points[i].Line, line, endLine)
			}
		}
	}

	for i := range points {
		if points[i].PairID == pairID && points[i].Status == PointActive {
			points[i].Status = PointSoftDeleted
		}
	}

	return duration.Unregister(pairID)
}

func hasDurationType(types []InstrumentType) bool {
	for _, t := range types {
		if t == Duration {
			return true
		}
	}
	return false
}
