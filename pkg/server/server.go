//go:build !go1.23

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/0xbu11/codebull/pkg/debugflag"
	"github.com/0xbu11/codebull/pkg/harvest"
	"github.com/0xbu11/codebull/pkg/instrument"
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
	Types             []string `json:"types,omitempty"`
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

	createPointFn           func(fileName, functionName string, line int, variableNames []string, collectStacktrace bool, types []instrument.InstrumentType) error
	createPointAtAddressFn  func(functionName string, addr uint64, variableNames []string, collectStacktrace bool, types []instrument.InstrumentType) error
	removePointByFunctionFn func(functionName string, line int) error
	removePointByAddressFn  func(functionName string, addr uint64) error
	listVariablesFn         func(functionName string, line int) ([]variable.VariableDTO, error)
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

	harvest.SetOnReport(s.Broadcast)

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

func toVariableDTOs(vars []*variable.Variable) []variable.VariableDTO {
	if len(vars) == 0 {
		return nil
	}

	dtos := make([]variable.VariableDTO, 0, len(vars))
	for _, v := range vars {
		if v == nil || v.Name == "" {
			continue
		}

		typeName := "unknown"
		if v.Type != nil {
			typeName = v.Type.String()
		}

		dtos = append(dtos, variable.VariableDTO{
			Name: v.Name,
			Type: typeName,
		})
	}

	return dtos
}

func (s *Server) listVariables(functionName string, line int) ([]variable.VariableDTO, error) {
	fn, err := s.manager.GetFunction(functionName)
	if err != nil {
		return nil, err
	}

	_ = line

	return toVariableDTOs(fn.Variables), nil
}

func (s *Server) HandleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"name": "Ego Shadow Process"})
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

	if pattern == "" || lineStr == "" {
		http.Error(w, "pattern and line are required", http.StatusBadRequest)
		return
	}

	var line int
	fmt.Sscanf(lineStr, "%d", &line)

	if r.Method == "GET" {
		createPoint := s.createPointFn
		if createPoint == nil {
			createPoint = s.manager.CreatePoint
		}
		if err := createPoint("", pattern, line, variableNames, collectStacktrace, []instrument.InstrumentType{instrument.Logging}); err != nil {
			code, status := classifyError(err)
			writeJSONError(w, status, code, fmt.Sprintf("failed to register trace: %v", err))
			debugflag.Printf("Failed to register trace %s:%d: %v", pattern, line, err)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		debugflag.Printf("Registered trace: %s:%d variables=%v collect_stacktrace=%t", pattern, line, variableNames, collectStacktrace)

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

	listVariables := s.listVariablesFn
	if listVariables == nil {
		listVariables = s.listVariables
	}

	variables, err := listVariables(pattern, line)
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
				err = createPointAtAddress(fName, p.Address, p.VariableNames, p.CollectStacktrace, p.Types)
			} else {
				createPoint := s.createPointFn
				if createPoint == nil {
					createPoint = s.manager.CreatePoint
				}
				err = createPoint(p.File, fName, p.Line, p.VariableNames, p.CollectStacktrace, p.Types)
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



	resp := map[string]interface{}{
		"function_name": data.FunctionName,
		"variables":     data.Variables,
	}
	if len(data.StackTrace) > 0 {
		resp["stacktrace"] = data.StackTrace
	}


	vars := make([]harvest.VariableValue, 0, len(data.Variables)+2)
	vars = append(vars, harvest.VariableValue{Name: "line", Value: fmt.Sprintf("%d", data.Line)})
	vars = append(vars, harvest.VariableValue{Name: "timestamp", Value: time.Now().Format(time.RFC3339)})
	vars = append(vars, data.Variables...)

	resp["variables"] = vars

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
