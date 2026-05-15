package e2e

import (
	"encoding/json"
	"fmt"
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

func TestSliceCapture(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Only supported on Linux")
	}

	rootDir, _ := os.Getwd()
	for !containsGoMod(rootDir) {
		rootDir = filepath.Dir(rootDir)
	}

	fixtureBin := filepath.Join(os.TempDir(), "ego-shadow-slice-test")
	
	buildCmd := exec.Command("go", "build",
		"-gcflags", "all=-N -l",
		"-ldflags", "-w=0 -s=0 -compressdwarf=false",
		"-o", fixtureBin,
		"./test/e2e/fixtures/slice",
	)
	buildCmd.Dir = rootDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Build failed: %v\nOutput: %s", err, string(out))
	}
	defer os.Remove(fixtureBin)

	listenAddr := freeLocalAddr(t)
	cmd := exec.Command(fixtureBin)
	cmd.Env = append(os.Environ(), "EGO_SHADOW_ADDR="+listenAddr, "EGO_SHADOW_DEBUG=1")
	
	debugLogPath := filepath.Join(rootDir, "slice_capture_debug.log")
	debugLog, _ := os.Create(debugLogPath)
	defer debugLog.Close()
	defer os.Remove(debugLogPath)
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

	srcFile := filepath.Join(rootDir, "test", "e2e", "fixtures", "slice", "main.go")
	line := findLineContaining(t, srcFile, "fmt.Printf(\"SliceTarget:")
	addr, err := findAddressForLine(fixtureBin, "test/e2e/fixtures/slice/main.go", line)
	if err != nil {
		t.Fatalf("Failed to find address for line %d: %v", line, err)
	}
	t.Logf("Registering tracepoint at %s:%d (addr=0x%x)", srcFile, line, addr)

	req := server.Request{
		Action: server.ActionRegister,
		Point: instrument.Point{
			Function: &function.Function{Name: "main.SliceTarget"},
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
			
			n := mustReadIntVar(t, vars, "n")
			t.Logf("Verifying trace for n=%d", n)

			intsVar := mustFindVarMap(t, vars, "ints")
			if intsVar["value"] != fmt.Sprintf("len=%d", n) {
				t.Errorf("ints: expected value len=%d, got %v", n, intsVar["value"])
			}
			for i := int64(0); i < n; i++ {
				val := mustReadChildIntVar(t, intsVar, fmt.Sprintf("[%d]", i))
				if val != i*10 {
					t.Errorf("ints[%d]: expected %d, got %d", i, i*10, val)
				}
			}

			stringsVar := mustFindVarMap(t, vars, "strings")
			expLen := int64(3)
			if n > 3 {
				expLen = 4
			}
			if stringsVar["value"] != fmt.Sprintf("len=%d", expLen) {
				t.Errorf("strings: expected value len=%d, got %v", expLen, stringsVar["value"])
			}
			s0 := mustReadChildStringVar(t, stringsVar, "[0]")
			if s0 != "hello" {
				t.Errorf("strings[0]: expected hello, got %s", s0)
			}

			structsVar := mustFindVarMap(t, vars, "structs")
			s1 := mustFindChildMap(t, structsVar, "[1]")
			s1ID := mustReadChildIntVar(t, s1, "ID")
			s1Name := mustReadChildStringVar(t, s1, "Name")
			if s1ID != 2 || s1Name != "second" {
				t.Errorf("structs[1]: expected {2, second}, got {%d, %s}", s1ID, s1Name)
			}

			nestedVar := mustFindVarMap(t, vars, "nested")
			row1 := mustFindChildMap(t, nestedVar, "[1]")
			row1_2 := mustReadChildIntVar(t, row1, "[2]")
			if row1_2 != 5 {
				t.Errorf("nested[1][2]: expected 5, got %d", row1_2)
			}

			largeVar := mustFindVarMap(t, vars, "large")
			if largeVar["value"] != "len=200" {
				t.Errorf("large: expected len=200, got %v", largeVar["value"])
			}
			children := largeVar["children"].([]any)
			if len(children) != 100 {
				t.Errorf("large children: expected 100 (capped), got %d", len(children))
			}

			break
		}
	}
}
