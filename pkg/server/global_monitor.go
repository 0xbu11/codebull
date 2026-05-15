package server

import (
	"fmt"
	"sync"
	"time"

	"github.com/0xbu11/codebull/pkg/debugflag"
	"github.com/0xbu11/codebull/pkg/function"
	"github.com/0xbu11/codebull/pkg/harvest"
)

type globalMonitorTask struct {
	variables []string
	interval  time.Duration
	lastRun   time.Time
}

type GlobalMonitorManager struct {
	mu       sync.Mutex
	tasks    map[string]*globalMonitorTask
	locator  *function.Locator
	stopCh   chan struct{}
	running  bool
	reporter func(harvest.ReportData)
}

func NewGlobalMonitorManager(locator *function.Locator, reporter func(harvest.ReportData)) *GlobalMonitorManager {
	return &GlobalMonitorManager{
		tasks:    make(map[string]*globalMonitorTask),
		locator:  locator,
		reporter: reporter,
	}
}

func (m *GlobalMonitorManager) Register(vars []string, intervalMs int) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := fmt.Sprintf("%v-%d", vars, intervalMs)
	m.tasks[key] = &globalMonitorTask{
		variables: vars,
		interval:  time.Duration(intervalMs) * time.Millisecond,
		lastRun:   time.Now(),
	}

	if !m.running {
		m.stopCh = make(chan struct{})
		m.running = true
		go m.run()
	}
}

func (m *GlobalMonitorManager) Unregister(vars []string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for k, t := range m.tasks {
		if sliceEqual(t.variables, vars) {
			delete(m.tasks, k)
		}
	}

	if len(m.tasks) == 0 && m.running {
		close(m.stopCh)
		m.running = false
	}
}

func (m *GlobalMonitorManager) run() {
	debugflag.Println("Global Monitor Worker started")
	ticker := time.NewTicker(200 * time.Millisecond) // Heartbeat
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			debugflag.Println("Global Monitor Worker stopped")
			return
		case now := <-ticker.C:
			m.mu.Lock()
			var tasksToRun []*globalMonitorTask
			for _, t := range m.tasks {
				if now.Sub(t.lastRun) >= t.interval {
					tasksToRun = append(tasksToRun, t)
					t.lastRun = now
				}
			}
			m.mu.Unlock()

			for _, t := range tasksToRun {
				m.collectAndReport(t)
			}
		}
	}
}

func (m *GlobalMonitorManager) collectAndReport(t *globalMonitorTask) {
	var reportVars []harvest.VariableValue
	
	for _, name := range t.variables {
		gv, err := m.locator.GetGlobalVariable(name)
		if err != nil {
			reportVars = append(reportVars, harvest.VariableValue{
				Name:       name,
				Value:      fmt.Sprintf("<Error: %v>", err),
				Unreadable: err.Error(),
			})
			continue
		}

		addr, err := gv.Evaluate(nil, 0, 0)
		if err == nil {
			gv.Addr = addr
		}
		
		if gv.Addr != 0 {
			gv.LoadValue()
		}
		
		reportVars = append(reportVars, harvest.ToVariableValue(gv))
	}

	if m.reporter != nil {
		m.reporter(harvest.ReportData{
			FunctionName: "@global",
			Line:         0,
			Variables:    reportVars,
		})
	}
}

func sliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
