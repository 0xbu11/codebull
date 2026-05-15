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

func TestPointerCapture(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Only supported on Linux")
	}

	rootDir, _ := os.Getwd()
	for !containsGoMod(rootDir) {
		rootDir = filepath.Dir(rootDir)
	}

	fixtureBin := filepath.Join(os.TempDir(), "ego-shadow-pointer-test")
	
	buildCmd := exec.Command("go", "build",
		"-gcflags", "all=-N -l",
		"-ldflags", "-w=0 -s=0 -compressdwarf=false",
		"-o", fixtureBin,
		"./test/e2e/fixtures/pointer",
	)
	buildCmd.Dir = rootDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Build failed: %v\nOutput: %s", err, string(out))
	}
	defer os.Remove(fixtureBin)

	listenAddr := freeLocalAddr(t)
	cmd := exec.Command(fixtureBin)
	cmd.Env = append(os.Environ(), "EGO_SHADOW_ADDR="+listenAddr, "EGO_SHADOW_DEBUG=1")
	
	debugLogPath := filepath.Join(rootDir, "pointer_capture_debug.log")
	debugLog, _ := os.Create(debugLogPath)
	defer debugLog.Close()
	cmd.Stdout = debugLog
	cmd.Stderr = debugLog

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

	srcFile := filepath.Join(rootDir, "test", "e2e", "fixtures", "pointer", "main.go")
	line := findLineContaining(t, srcFile, "fmt.Printf(\"PointerTarget:")
	addr, err := findAddressForLine(fixtureBin, "test/e2e/fixtures/pointer/main.go", line)
	if err != nil {
		t.Fatalf("Failed to find address for line %d: %v", line, err)
	}
	t.Logf("Registering tracepoint at %s:%d (addr=0x%x)", srcFile, line, addr)

	req := server.Request{
		Action: server.ActionRegister,
		Point: instrument.Point{
			Function: &function.Function{Name: "main.PointerTarget"},
			Line:     line,
			Address:  addr,
			Types:    []instrument.InstrumentType{instrument.Logging},
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
		t.Fatalf("Register tracepoint failed: %s", resp.Message)
	}

	ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage failed: %v", err)
		}

		var m map[string]any
		if err := json.Unmarshal(msg, &m); err != nil {
			continue
		}

		if m["type"] == "report" {
			data := m["data"].(map[string]any)
			vars := data["variables"].([]any)
			
			val := mustReadIntVar(t, vars, "val")
			t.Logf("Verifying trace for val=%d", val)

			sVar := mustFindVarMap(t, vars, "s")
			if sVar["unreadable"] != nil {
				t.Errorf("s is unreadable: %v", sVar["unreadable"])
			}
			children, ok := sVar["children"].([]any)
			if !ok || len(children) == 0 {
				t.Errorf("s has no children (dereference failed?)")
			} else {
				deref := children[0].(map[string]any)
				count := mustReadChildIntVar(t, deref, "Count")
				if count != val {
					t.Errorf("s.Count: expected %d, got %d", val, count)
				}
			}

			ptrVar := mustFindVarMap(t, vars, "ptr")
			ptrChildren, ok := ptrVar["children"].([]any)
			if !ok || len(ptrChildren) == 0 {
				t.Errorf("ptr has no children")
			} else {
				derefVal := mustReadChildIntVar(t, ptrVar, "") // child of pointer has empty name usually
				if derefVal != val {
					t.Errorf("*ptr: expected %d, got %d", val, derefVal)
				}
			}

			break
		}
	}
}
