//go:build !go1.27

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0xbu11/codebull/pkg/debugflag"
	"github.com/0xbu11/codebull/pkg/duration"
	"github.com/0xbu11/codebull/pkg/function"
	"github.com/0xbu11/codebull/pkg/harvest"
	"github.com/0xbu11/codebull/pkg/instrument"
	"github.com/0xbu11/codebull/pkg/ratelimit"
	"github.com/0xbu11/codebull/pkg/codebull"
	"github.com/0xbu11/codebull/pkg/variable"
	"github.com/gorilla/websocket"
)

type Request struct {
	Action string           `json:"action"`
	Point  instrument.Point `json:"point"`
}

type Response struct {
	Status  string `json:"status"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

const (
	ErrCodeCopyLimitExceeded = "COPY_LIMIT_EXCEEDED"
)

type traceStatusResponse struct {
	Status            string   `json:"status"`
	Pattern           string   `json:"pattern"`
	Line              int      `json:"line"`
	Instrumented      bool     `json:"instrumented"`
	Address           uint64   `json:"address,omitempty"`
	VariableNames     []string `json:"variable_names,omitempty"`
	CollectStacktrace bool     `json:"collect_stacktrace"`
	Types             []string           `json:"types,omitempty"`
	RateLimit         *ratelimit.Config  `json:"rate_limit,omitempty"`
	EndLine           int                `json:"end_line,omitempty"`
	Duration          *durationStatus    `json:"duration,omitempty"`
	Sampling          *samplingStatus    `json:"sampling,omitempty"`
}

// samplingStatus tells a caller how much of what happened it is actually
// looking at. Hits is exact; Collected is what survived the limiter.
type samplingStatus struct {
	Hits      int64   `json:"hits"`
	Collected int64   `json:"collected"`
	Dropped   int64   `json:"dropped"`
	Ratio     float64 `json:"ratio"`
	Complete  bool    `json:"complete"`
}

func buildSamplingStatus(s ratelimit.Stats) *samplingStatus {
	return &samplingStatus{
		Hits:      s.Hits,
		Collected: s.Allowed,
		Dropped:   s.Dropped,
		Ratio:     s.SamplingRatio(),
		Complete:  s.Complete(),
	}
}

type durationStatus struct {
	PairID       uint64 `json:"pair_id"`
	PendingPairs int    `json:"pending_pairs"`
	duration.Stats
}

type variableInformationResponse struct {
	Status    string                 `json:"status"`
	Pattern   string                 `json:"pattern"`
	Line      int                    `json:"line"`
	Variables []variable.VariableDTO `json:"variables"`
}

const (
	ActionRegister   = "register"
	ActionUnregister = "unregister"
	ActionRegisterGlobal   = "register_global_monitor"
	ActionUnregisterGlobal = "unregister_global_monitor"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for now
	},
}

type Server struct {
	manager   *instrument.Manager
	clients   map[*websocket.Conn]*wsClient
	clientsMu sync.RWMutex

	createPointFn           func(fileName, functionName string, line int, variableNames []string, collectStacktrace bool, types []instrument.InstrumentType, ratelimitCfg *ratelimit.Config) error
	createPointAtAddressFn  func(functionName string, addr uint64, variableNames []string, collectStacktrace bool, types []instrument.InstrumentType, ratelimitCfg *ratelimit.Config) error
	removePointByFunctionFn func(functionName string, line int) error
	removePointByAddressFn  func(functionName string, addr uint64) error
	listVariablesFn         func(functionName string, line int, layer int) ([]variable.VariableDTO, error)
	createDurationPointFn   func(fileName, functionName string, line, endLine int, ratelimitCfg *ratelimit.Config) error
	removeDurationPointFn   func(functionName string, line, endLine int) error

	globalMonitor *GlobalMonitorManager
}

type wsClient struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

func NewServer(manager *instrument.Manager) *Server {
	s := &Server{
		manager: manager,
		clients: make(map[*websocket.Conn]*wsClient),
	}

	locator, _ := function.NewLocatorForSelf() // Or use manager's locator if available
	s.globalMonitor = NewGlobalMonitorManager(locator, s.Broadcast)

	harvest.SetOnReport(s.Broadcast)

	duration.SetOnSample(func(sm duration.Sample) {
		s.Broadcast(harvest.ReportData{
			FunctionName: sm.FunctionName,
			Line:         sm.EntryLine,
			Variables: []harvest.VariableValue{
				{Name: "__duration_ns", Value: strconv.FormatInt(sm.DurationNs, 10), Type: "int64"},
				{Name: "__goid", Value: strconv.FormatInt(sm.Goid, 10), Type: "int64"},
			},
		})
	})

	return s
}

func parseVariableNames(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(values))
	var variableNames []string
	for _, raw := range values {
		for _, name := range strings.Split(raw, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			variableNames = append(variableNames, name)
		}
	}

	return variableNames
}

func parseCollectStacktrace(value string) (bool, error) {
	if value == "" {
		return false, nil
	}
	return strconv.ParseBool(value)
}

// parseRateLimitQuery reads an optional per-point budget off the registration
// URL. Without it the point inherits the registry default, which is applied per
// point rather than shared, so attaching another point never shrinks this one's
// budget.
func parseRateLimitQuery(query url.Values) (*ratelimit.Config, error) {
	rateStr := query.Get("rate")
	if rateStr == "" {
		return nil, nil
	}

	rate, err := strconv.ParseFloat(rateStr, 64)
	if err != nil || rate < 0 {
		return nil, fmt.Errorf("rate must be a non-negative number")
	}

	cfg := ratelimit.Config{Algorithm: "token_bucket", Rate: rate}
	if algo := query.Get("rate_algorithm"); algo != "" {
		cfg.Algorithm = algo
	}
	if burstStr := query.Get("burst"); burstStr != "" {
		burst, err := strconv.Atoi(burstStr)
		if err != nil || burst < 0 {
			return nil, fmt.Errorf("burst must be a non-negative integer")
		}
		cfg.Burst = burst
	}
	if windowStr := query.Get("rate_window_ms"); windowStr != "" {
		ms, err := strconv.Atoi(windowStr)
		if err != nil || ms <= 0 {
			return nil, fmt.Errorf("rate_window_ms must be a positive integer")
		}
		cfg.Window = time.Duration(ms) * time.Millisecond
	}
	return &cfg, nil
}


func (s *Server) listVariables(functionName string, line int, layer int) ([]variable.VariableDTO, error) {
	fn, err := s.manager.GetFunction(functionName)
	if err != nil {
		return nil, err
	}

	_ = line

	return variable.BuildDTOs(fn.Variables, layer), nil
}

func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"name": "Ego Shadow Process",
		"duration_available": duration.RuntimeHooksReady(),
	})
}

func (s *Server) HandleTrace(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	query := r.URL.Query()
	pattern := query.Get("pattern")
	lineStr := query.Get("line")
	variableNames := parseVariableNames(query["variable"])
	collectStacktrace, err := parseCollectStacktrace(query.Get("collect_stacktrace"))
	if err != nil {
		http.Error(w, "collect_stacktrace must be a valid boolean", http.StatusBadRequest)
		return
	}
	rateLimitCfg, err := parseRateLimitQuery(query)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if pattern == "" || lineStr == "" {
		http.Error(w, "pattern and line are required", http.StatusBadRequest)
		return
	}

	var line int
	fmt.Sscanf(lineStr, "%d", &line)

	pointType := query.Get("type")
	endLine := 0
	if raw := query.Get("end_line"); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 {
			http.Error(w, "end_line must be a positive integer", http.StatusBadRequest)
			return
		}
		endLine = parsed
	}
	if pointType == "duration" && (r.Method == "GET" || r.Method == "DELETE") {
		s.handleDurationTrace(w, r, pattern, line, endLine, rateLimitCfg)
		return
	}

	if r.Method == "GET" {
		createPoint := s.createPointFn
		if createPoint == nil {
			createPoint = s.manager.CreatePoint
		}
		if err := createPoint("", pattern, line, variableNames, collectStacktrace, []instrument.InstrumentType{instrument.Logging}, rateLimitCfg); err != nil {
			code, status := classifyError(err)
			writeJSONError(w, status, code, fmt.Sprintf("failed to register trace: %v", err))
			debugflag.Printf("Failed to register trace %s:%d: %v", pattern, line, err)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		debugflag.Printf("Registered trace: %s:%d variables=%v collect_stacktrace=%t", pattern, line, variableNames, collectStacktrace)

	} else if r.Method == "POST" {
		var req struct {
			Point struct {
				Pattern           string            `json:"pattern"`
				Line              int               `json:"line"`
				VariableNames     []string          `json:"variable_names"`
				CollectStacktrace bool              `json:"collect_stacktrace"`
				RateLimit         *ratelimit.Config `json:"rate_limit"`
			} `json:"point"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		p := req.Point
		createPoint := s.createPointFn
		if createPoint == nil {
			createPoint = s.manager.CreatePoint
		}
		if err := createPoint("", p.Pattern, p.Line, p.VariableNames, p.CollectStacktrace, []instrument.InstrumentType{instrument.Logging}, p.RateLimit); err != nil {
			code, status := classifyError(err)
			writeJSONError(w, status, code, fmt.Sprintf("failed to register trace: %v", err))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		debugflag.Printf("Registered trace (via POST): %s:%d variables=%v ratelimit=%v", p.Pattern, p.Line, p.VariableNames, p.RateLimit)

	} else if r.Method == "DELETE" {
		removePointByFunction := s.removePointByFunctionFn
		if removePointByFunction == nil {
			removePointByFunction = s.manager.RemovePointByFunction
		}
		if err := removePointByFunction(pattern, line); err != nil {
			code, status := classifyError(err)
			writeJSONError(w, status, code, fmt.Sprintf("failed to unregister trace: %v", err))
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		debugflag.Printf("Unregistered trace: %s:%d", pattern, line)
	} else {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleDurationTrace(w http.ResponseWriter, r *http.Request, pattern string, line, endLine int, rateLimitCfg *ratelimit.Config) {
	if endLine <= 0 {
		http.Error(w, "end_line is required for type=duration", http.StatusBadRequest)
		return
	}

	if r.Method == "GET" {
		createDuration := s.createDurationPointFn
		if createDuration == nil {
			createDuration = s.manager.CreateDurationPoint
		}
		if err := createDuration("", pattern, line, endLine, rateLimitCfg); err != nil {
			code, status := classifyError(err)
			writeJSONError(w, status, code, fmt.Sprintf("failed to register duration trace: %v", err))
			debugflag.Printf("Failed to register duration trace %s:%d-%d: %v", pattern, line, endLine, err)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		debugflag.Printf("Registered duration trace: %s:%d-%d", pattern, line, endLine)
		return
	}

	removeDuration := s.removeDurationPointFn
	if removeDuration == nil {
		removeDuration = s.manager.RemoveDurationPoint
	}
	if err := removeDuration(pattern, line, endLine); err != nil {
		code, status := classifyError(err)
		writeJSONError(w, status, code, fmt.Sprintf("failed to unregister duration trace: %v", err))
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	debugflag.Printf("Unregistered duration trace: %s:%d-%d", pattern, line, endLine)
}

func (s *Server) HandleTraceStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	pattern := query.Get("pattern")
	lineStr := query.Get("line")

	if pattern == "" || lineStr == "" {
		http.Error(w, "pattern and line are required", http.StatusBadRequest)
		return
	}

	line, err := strconv.Atoi(lineStr)
	if err != nil {
		http.Error(w, "line must be a valid integer", http.StatusBadRequest)
		return
	}

	resp := traceStatusResponse{
		Status:       "ok",
		Pattern:      pattern,
		Line:         line,
		Instrumented: false,
	}

	points := s.manager.GetPoints(pattern)
	for _, point := range points {
		if point.Line != line {
			continue
		}
		resp.Instrumented = true
		resp.Address = point.Address
		resp.VariableNames = append([]string(nil), point.VariableNames...)
		resp.CollectStacktrace = point.CollectStacktrace
		for _, t := range point.Types {
			resp.Types = append(resp.Types, t.String())
		}
		// Duration pairs are accounted at the exit trap, so the counters for a
		// latency point live under its exit PC rather than the entry address.
		statsPC := point.Address
		if point.PairID != 0 {
			if meta, ok := duration.LookupPC(point.Address); ok && meta.ExitPC != 0 {
				statsPC = meta.ExitPC
			}
		}
		resp.RateLimit = ratelimit.Global().GetConfig(statsPC)
		resp.Sampling = buildSamplingStatus(ratelimit.Global().StatsFor(statsPC))
		if point.PairID != 0 {
			if meta, ok := duration.LookupPC(point.Address); ok {
				resp.EndLine = meta.EndLine
			}
			resp.Duration = &durationStatus{
				PairID:       point.PairID,
				PendingPairs: duration.PendingCount(point.PairID),
				Stats:        duration.GetStats(),
			}
		}
		break
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func (s *Server) HandleVariableInformation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	pattern := query.Get("pattern")
	lineStr := query.Get("line")

	if pattern == "" || lineStr == "" {
		http.Error(w, "pattern and line are required", http.StatusBadRequest)
		return
	}

	line, err := strconv.Atoi(lineStr)
	if err != nil {
		http.Error(w, "line must be a valid integer", http.StatusBadRequest)
		return
	}

	layer := 0
	if layerStr := query.Get("layer"); layerStr != "" {
		if l, err := strconv.Atoi(layerStr); err == nil {
			layer = l
		}
	}

	listVariables := s.listVariablesFn
	if listVariables == nil {
		listVariables = s.listVariables
	}

	variables, err := listVariables(pattern, line, layer)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "", fmt.Sprintf("failed to load variable information: %v", err))
		return
	}

	resp := variableInformationResponse{
		Status:    "ok",
		Pattern:   pattern,
		Line:      line,
		Variables: variables,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func (s *Server) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		debugflag.Printf("upgrade error: %v", err)
		return
	}
	client := &wsClient{conn: conn}

	s.clientsMu.Lock()
	s.clients[conn] = client
	s.clientsMu.Unlock()

	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, conn)
		s.clientsMu.Unlock()
		conn.Close()
	}()

	for {
		var req Request
		err := conn.ReadJSON(&req)
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				debugflag.Printf("read error: %v", err)
			}
			break
		}

		var resp Response
		switch req.Action {
		case ActionRegister:
			p := req.Point
			fName := ""
			if p.Function != nil {
				fName = p.Function.Name
			}

			if p.Address != 0 {
				createPointAtAddress := s.createPointAtAddressFn
				if createPointAtAddress == nil {
					createPointAtAddress = s.manager.CreatePointAtAddress
				}
				err = createPointAtAddress(fName, p.Address, p.VariableNames, p.CollectStacktrace, p.Types, p.RateLimit)
			} else {
				createPoint := s.createPointFn
				if createPoint == nil {
					createPoint = s.manager.CreatePoint
				}
				err = createPoint(p.File, fName, p.Line, p.VariableNames, p.CollectStacktrace, p.Types, p.RateLimit)
			}

			if err != nil {
				code, _ := classifyError(err)
				resp = Response{Status: "error", Code: code, Message: err.Error()}
			} else {
				resp = Response{Status: "success"}
			}

		case ActionUnregister:
			p := req.Point
			fName := ""
			if p.Function != nil {
				fName = p.Function.Name
			}

			if p.Address != 0 {
				removePointByAddress := s.removePointByAddressFn
				if removePointByAddress == nil {
					removePointByAddress = s.manager.RemovePointByAddress
				}
				err = removePointByAddress(fName, p.Address)
			} else {
				removePointByFunction := s.removePointByFunctionFn
				if removePointByFunction == nil {
					removePointByFunction = s.manager.RemovePointByFunction
				}
				err = removePointByFunction(fName, p.Line)
			}
			if err != nil {
				code, _ := classifyError(err)
				resp = Response{Status: "error", Code: code, Message: err.Error()}
			} else {
				resp = Response{Status: "success"}
			}

		case ActionRegisterGlobal:
			s.globalMonitor.Register(req.Point.VariableNames, req.Point.Line)
			resp = Response{Status: "success"}

		case ActionUnregisterGlobal:
			s.globalMonitor.Unregister(req.Point.VariableNames)
			resp = Response{Status: "success"}

		default:
			continue
		}

		client.mu.Lock()
		writeErr := conn.WriteJSON(resp)
		client.mu.Unlock()
		if writeErr != nil {
			debugflag.Printf("write response error: %v", writeErr)
			break
		}
	}
}

func classifyError(err error) (string, int) {
	if errors.Is(err, codebull.ErrCopyFunctionLimitExceeded) {
		return ErrCodeCopyLimitExceeded, http.StatusTooManyRequests
	}
	return "", http.StatusInternalServerError
}

func writeJSONError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(Response{Status: "error", Code: code, Message: message})
}

func (s *Server) Broadcast(data harvest.ReportData) {

	reportData := map[string]interface{}{
		"function_name": data.FunctionName,
		"line":          data.Line,
		"timestamp":     time.Now().Format(time.RFC3339),
		"variables":     data.Variables,
	}
	if len(data.StackTrace) > 0 {
		reportData["stacktrace"] = data.StackTrace
	}

	resp := map[string]interface{}{
		"type":          "report",
		"data":          reportData,
		"function_name": data.FunctionName,
		"line":          data.Line,
		"variables":     data.Variables,
	}

	if len(data.StackTrace) > 0 {
		resp["stacktrace"] = data.StackTrace
	}

	s.clientsMu.RLock()
	defer s.clientsMu.RUnlock()

	for conn, client := range s.clients {
		client.mu.Lock()
		err := conn.WriteJSON(resp)
		client.mu.Unlock()
		if err != nil {
			debugflag.Printf("write error: %v", err)
			conn.Close()
		}
	}
}

func (s *Server) HandleRateLimitStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	reg := ratelimit.Global()
	snap := reg.Snapshot()

	// Resolve each counted address back to the pattern/line it was registered
	// under, so a caller can join these counters onto its own tracepoint list.
	// A latency pair is accounted at its exit trap, so map that address too.
	type located struct {
		pattern string
		line    int
	}
	byPC := make(map[uint64]located)
	for _, np := range s.manager.AllPoints() {
		byPC[np.Point.Address] = located{pattern: np.Pattern, line: np.Point.Line}
		if np.Point.PairID != 0 {
			if meta, ok := duration.LookupPC(np.Point.Address); ok && meta.ExitPC != 0 {
				byPC[meta.ExitPC] = located{pattern: np.Pattern, line: np.Point.Line}
			}
		}
	}

	points := make([]ratePointStatus, 0, len(snap.Points))
	for _, p := range snap.Points {
		ps := ratePointStatus{
			PC:            fmt.Sprintf("0x%x", p.PC),
			Config:        p.Config,
			Explicit:      p.Explicit,
			Hits:          p.Hits,
			Collected:     p.Allowed,
			Dropped:       p.Dropped,
			SamplingRatio: p.SamplingRatio(),
		}
		if loc, ok := byPC[p.PC]; ok {
			ps.Function = loc.pattern
			ps.Line = loc.line
		} else {
			if fn := runtime.FuncForPC(uintptr(p.PC)); fn != nil {
				ps.Function = strings.TrimPrefix(fn.Name(), "shadow-")
			}
			if line, ok := instrument.GetPointLineAtPC(p.PC); ok {
				ps.Line = line
			}
		}
		points = append(points, ps)
	}
	sort.Slice(points, func(i, j int) bool {
		if points[i].Dropped != points[j].Dropped {
			return points[i].Dropped > points[j].Dropped
		}
		return points[i].Function < points[j].Function
	})

	resp := map[string]interface{}{
		"status": "ok",
		// "global" keeps its original meaning for existing clients: the config a
		// point gets when it has none of its own. It is now applied per point.
		"global":          snap.Default,
		"default":         snap.Default,
		"scope":           "per_point",
		"ceiling":         snap.Ceiling,
		"ceiling_dropped": snap.CeilingDropped,
		"since":           snap.Since.UTC().Format(time.RFC3339Nano),
		"totals": map[string]interface{}{
			"hits":      snap.Totals.Hits,
			"collected": snap.Totals.Allowed,
			"dropped":   snap.Totals.Dropped,
			"complete":  snap.Totals.Complete(),
		},
		"points": points,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ratePointStatus is one instrumented address as reported by /ratelimit/status.
// Counters are cumulative since `since`; diff two reads for a window.
type ratePointStatus struct {
	PC            string           `json:"pc"`
	Function      string           `json:"function,omitempty"`
	Line          int              `json:"line,omitempty"`
	Config        ratelimit.Config `json:"config"`
	Explicit      bool             `json:"explicit"`
	Hits          int64            `json:"hits"`
	Collected     int64            `json:"collected"`
	Dropped       int64            `json:"dropped"`
	SamplingRatio float64          `json:"sampling_ratio"`
}

func (s *Server) HandleRateLimitUpdate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var body struct {
		ratelimit.Config
		// Scope selects what the config applies to: "default" (every point
		// without its own budget), "ceiling" (the process-wide safety net), or
		// "point" together with pattern/line.
		Scope   string `json:"scope,omitempty"`
		Pattern string `json:"pattern,omitempty"`
		Line    int    `json:"line,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	cfg := body.Config
	switch body.Scope {
	case "", "default", "global":
		ratelimit.Global().SetDefaultLimiter(&cfg)
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "scope": "default", "applied": cfg})

	case "ceiling":
		ratelimit.Global().SetCeilingLimiter(&cfg)
		json.NewEncoder(w).Encode(map[string]any{"status": "ok", "scope": "ceiling", "applied": cfg})

	case "point":
		if body.Pattern == "" || body.Line <= 0 {
			writeJSONError(w, http.StatusBadRequest, "INVALID_ARGUMENT",
				"scope=point needs pattern and line naming an attached tracepoint")
			return
		}
		applied := 0
		for _, point := range s.manager.GetPoints(body.Pattern) {
			if point.Line != body.Line {
				continue
			}
			pc := point.Address
			if point.PairID != 0 {
				if meta, ok := duration.LookupPC(point.Address); ok && meta.ExitPC != 0 {
					pc = meta.ExitPC
				}
			}
			ratelimit.Global().Register(pc, cfg)
			applied++
		}
		if applied == 0 {
			writeJSONError(w, http.StatusNotFound, "NOT_FOUND",
				fmt.Sprintf("no tracepoint attached at %s:%d", body.Pattern, body.Line))
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ok", "scope": "point",
			"pattern": body.Pattern, "line": body.Line, "applied": cfg,
		})

	default:
		writeJSONError(w, http.StatusBadRequest, "INVALID_ARGUMENT",
			fmt.Sprintf("unknown scope %q; expected default, ceiling or point", body.Scope))
	}
}
