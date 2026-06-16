package e2e

import (
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/0xbu11/codebull/pkg/function"
	"github.com/0xbu11/codebull/pkg/instrument"
	"github.com/0xbu11/codebull/pkg/server"
	"github.com/gorilla/websocket"
)

func TestCoreDataStructures(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Only supported on Linux")
	}

	rootDir, _ := os.Getwd()
	for !containsGoMod(rootDir) {
		rootDir = filepath.Dir(rootDir)
	}

	fixtureBin := filepath.Join(os.TempDir(), "ego-shadow-corestruct-test")

	buildCmd := exec.Command("go", "build",
		"-gcflags", "all=-N -l",
		"-ldflags", "-w=0 -s=0 -compressdwarf=false",
		"-o", fixtureBin,
		"./test/e2e/fixtures/corestruct",
	)
	buildCmd.Dir = rootDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Build failed: %v\nOutput: %s", err, string(out))
	}
	defer os.Remove(fixtureBin)

	testCases := []struct {
		funcName     string
		variableName string
		verify       func(t *testing.T, data map[string]any)
	}{
		{
			funcName:     "main.useMap",
			variableName: "m",
			verify: func(t *testing.T, data map[string]any) {
				vars, ok := data["variables"].([]any)
				if !ok || len(vars) == 0 {
					t.Fatalf("Expected variables in payload")
				}
				v := vars[0].(map[string]any)
				if v["name"] != "m" {
					t.Errorf("Expected variable name 'm', got %v", v["name"])
				}
				if typ, _ := v["type"].(string); typ != "map[int]string" {
					t.Errorf("Expected variable type 'map[int]string', got %v", typ)
				}
				t.Logf("Successfully captured map: %+v", v)
			},
		},
		{
			funcName:     "main.useChan",
			variableName: "c",
			verify: func(t *testing.T, data map[string]any) {
				vars, ok := data["variables"].([]any)
				if !ok || len(vars) == 0 {
					t.Fatalf("Expected variables in payload")
				}
				v := vars[0].(map[string]any)
				if v["name"] != "c" {
					t.Errorf("Expected variable name 'c', got %v", v["name"])
				}
				if typ, _ := v["type"].(string); typ != "chan int" {
					t.Errorf("Expected variable type 'chan int', got %v", typ)
				}
				t.Logf("Successfully captured channel: %+v", v)
			},
		},
		{
			funcName:     "main.useInterface",
			variableName: "i",
			verify: func(t *testing.T, data map[string]any) {
				vars, ok := data["variables"].([]any)
				if !ok || len(vars) == 0 {
					t.Fatalf("Expected variables in payload")
				}
				v := vars[0].(map[string]any)
				if v["name"] != "i" {
					t.Errorf("Expected variable name 'i', got %v", v["name"])
				}
				if typ, _ := v["type"].(string); typ != "interface {}" {
					t.Errorf("Expected variable type 'interface {}', got %v", typ)
				}
				
				if unreadable, ok := v["unreadable"].(string); ok && unreadable != "" {
					t.Errorf("Interface value should be readable now, got: %s", unreadable)
				}
				
				valStr, _ := v["value"].(string)
				if valStr != "test_interface_string" {
					t.Errorf("Expected interface value to be 'test_interface_string', got: %v", valStr)
				}
				
				t.Logf("Successfully captured interface: %+v", v)
			},
		},
		{
			funcName:     "runtime.newproc1",
			variableName: "callergp",
			verify: func(t *testing.T, data map[string]any) {
				t.Fatalf("runtime.newproc1 should have been rejected")
			},
		},
		{
			funcName:     "main.useMap", // Safe tracepoint
			variableName: "runtime.allp", // Request a global variable
			verify: func(t *testing.T, data map[string]any) {
				vars, ok := data["variables"].([]any)
				if !ok || len(vars) == 0 {
					t.Fatalf("Expected variables in payload")
				}
				
				var found bool
				for _, vAny := range vars {
					v := vAny.(map[string]any)
					if v["name"] == "runtime.allp" {
						found = true
						if typ, _ := v["type"].(string); typ != "struct []*runtime.p" && typ != "[]*runtime.p" {
							t.Errorf("Expected variable type 'struct []*runtime.p', got %v", typ)
						}
						
						children, ok := v["children"].([]any)
						if !ok {
							t.Logf("Warning: runtime.allp has no children or is unreadable. Payload: %+v", v)
						} else {
							t.Logf("Successfully captured runtime.allp with %d processors", len(children))
						}
						break
					}
				}
				if !found {
					t.Errorf("Could not find 'runtime.allp' in payload")
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.funcName, func(t *testing.T) {
			listenAddr := freeLocalAddr(t)
			cmd := exec.Command(fixtureBin)
			cmd.Env = append(os.Environ(), "EGO_SHADOW_ADDR="+listenAddr, "EGO_SHADOW_DEBUG=1")
			
			logPath := filepath.Join(rootDir, "corestruct_test_"+tc.funcName+".log")
			logFile, _ := os.Create(logPath)
			defer logFile.Close()
			cmd.Stdout = logFile
			cmd.Stderr = logFile

			if err := cmd.Start(); err != nil {
				t.Fatalf("Start failed: %v", err)
			}
			defer cmd.Process.Kill()

			waitForHealth(t, "http://"+listenAddr+"/health", 5*time.Second)

			u := url.URL{Scheme: "ws", Host: listenAddr, Path: "/ws"}
			ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
			if err != nil {
				t.Fatalf("Dial failed: %v", err)
			}
			defer ws.Close()

			addr, err := findFunctionAddress(fixtureBin, tc.funcName)
			if err != nil {
				t.Fatalf("Failed to find address for %s: %v", tc.funcName, err)
			}

			req := server.Request{
				Action: server.ActionRegister,
				Point: instrument.Point{
					Function:      &function.Function{Name: tc.funcName},
					Address:       addr,
					VariableNames: []string{tc.variableName},
					Types:         []instrument.InstrumentType{instrument.Logging},
				},
			}
			if err := ws.WriteJSON(req); err != nil {
				t.Fatalf("Register failed: %v", err)
			}

			var resp server.Response
			if err := ws.ReadJSON(&resp); err != nil {
				t.Fatalf("Read register response failed: %v", err)
			}
			if resp.Status == "error" {
				if tc.funcName == "runtime.newproc1" {
					t.Logf("Correctly rejected blacklisted function %s: %s", tc.funcName, resp.Message)
					return
				}
				t.Fatalf("Register tracepoint failed: %s", resp.Message)
			}

			ws.SetReadDeadline(time.Now().Add(5 * time.Second))
			found := false
			for !found {
				_, msg, err := ws.ReadMessage()
				if err != nil {
					t.Fatalf("Failed to receive report: %v", err)
				}

				var m map[string]any
				if err := json.Unmarshal(msg, &m); err != nil {
					continue
				}

				if m["type"] == "report" {
					data := m["data"].(map[string]any)
					if data["function_name"] == tc.funcName {
						tc.verify(t, data)
						found = true
					}
				}
			}
		})
	}
}

func getFieldNames(children []any) []string {
	var names []string
	for _, c := range children {
		if m, ok := c.(map[string]any); ok {
			if name, ok := m["name"].(string); ok {
				names = append(names, name)
			}
		}
	}
	return names
}

