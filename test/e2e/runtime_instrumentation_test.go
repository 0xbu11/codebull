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

func TestRuntimeInstrumentation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Only supported on Linux")
	}

	rootDir, _ := os.Getwd()
	for !containsGoMod(rootDir) {
		rootDir = filepath.Dir(rootDir)
	}

	fixtureBin := filepath.Join(os.TempDir(), "ego-shadow-runtime-test")
	
	buildCmd := exec.Command("go", "build",
		"-gcflags", "all=-N -l",
		"-ldflags", "-w=0 -s=0 -compressdwarf=false",
		"-o", fixtureBin,
		"./test/e2e/fixtures/runtime",
	)
	buildCmd.Dir = rootDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Build failed: %v\nOutput: %s", err, string(out))
	}
	defer os.Remove(fixtureBin)

	listenAddr := freeLocalAddr(t)
	_ = listenAddr

	funcs := []string{
		"runtime.NumGoroutine",
		"runtime.GC",
		"runtime.ReadMemStats",
		"runtime.Gosched",
		"runtime.newobject",
		"runtime.makechan",
		"runtime.chansend1",
		"runtime.chanrecv1",
		"runtime.mallocgc",
		"runtime.gopark",
		"runtime.schedule",
	}

	for _, funcName := range funcs {
		t.Run(funcName, func(t *testing.T) {
			listenAddr := freeLocalAddr(t)
			cmd := exec.Command(fixtureBin)
			cmd.Env = append(os.Environ(), "EGO_SHADOW_ADDR="+listenAddr, "EGO_SHADOW_DEBUG=1")
			
			logPath := filepath.Join(rootDir, "runtime_test_"+funcName+".log")
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

			addr, err := findFunctionAddress(fixtureBin, funcName)
			if err != nil {
				t.Fatalf("Failed to find address for %s: %v", funcName, err)
			}
			t.Logf("Registering tracepoint for %s at 0x%x", funcName, addr)

			req := server.Request{
				Action: server.ActionRegister,
				Point: instrument.Point{
					Function: &function.Function{Name: funcName},
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
				if isBlacklistedName(funcName) {
					t.Logf("Correctly rejected blacklisted function %s: %s", funcName, resp.Message)
					return
				}
				t.Fatalf("Register tracepoint failed: %s", resp.Message)
			}

			if isBlacklistedName(funcName) {
				t.Fatalf("Function %s should have been blacklisted but was accepted", funcName)
			}

			ws.SetReadDeadline(time.Now().Add(5 * time.Second))
			found := false
			for !found {
				_, msg, err := ws.ReadMessage()
				if err != nil {
					t.Fatalf("Failed to receive report for %s: %v. Check log: %s", funcName, err, logPath)
				}

				var m map[string]any
				if err := json.Unmarshal(msg, &m); err != nil {
					continue
				}

				if m["type"] == "report" {
					data := m["data"].(map[string]any)
					if data["function_name"] == funcName {
						t.Logf("Successfully captured report from %s", funcName)
						found = true
					}
				}
			}
		})
	}
}

func isBlacklistedName(name string) bool {
	blacklist := map[string]struct{}{
		"runtime.mallocgc":    {},
		"runtime.newobject":   {},
		"runtime.makechan":    {},
		"runtime.chansend1":   {},
		"runtime.chanrecv1":   {},
		"runtime.gopark":      {},
		"runtime.schedule":    {},
		"runtime.morestack":   {},
		"runtime.systemstack": {},
	}
	_, ok := blacklist[name]
	return ok
}
