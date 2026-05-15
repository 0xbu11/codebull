package e2e

import (
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xbu11/codebull/pkg/instrument"
	"github.com/0xbu11/codebull/pkg/server"
	"github.com/gorilla/websocket"
)

func TestGlobalMonitorService(t *testing.T) {
	rootDir, _ := os.Getwd()
	for !containsGoMod(rootDir) {
		rootDir = filepath.Dir(rootDir)
	}

	fixtureBin := filepath.Join(os.TempDir(), "ego-shadow-global-monitor-test")

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

	listenAddr := freeLocalAddr(t)
	cmd := exec.Command(fixtureBin)
	cmd.Env = append(os.Environ(), "EGO_SHADOW_ADDR="+listenAddr, "EGO_SHADOW_DEBUG=1")
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

	targetVars := []string{
		"runtime.allp",
		"runtime.allgs",
		"runtime.sched",
		"runtime.gomaxprocs",
		"runtime.ncpu",
	}
	req := server.Request{
		Action: "register_global_monitor",
		Point: instrument.Point{
			VariableNames: targetVars,
			Line:          500, // Used as interval_ms
		},
	}
	if err := ws.WriteJSON(req); err != nil {
		t.Fatalf("Register global failed: %v", err)
	}

	reportsCount := 0
	timeout := time.After(8 * time.Second)
	
	for reportsCount < 2 { // We want at least 2 full reports
		select {
		case <-timeout:
			t.Fatalf("Timeout waiting for periodic reports, only got %d", reportsCount)
		default:
			_, msg, err := ws.ReadMessage()
			if err != nil {
				t.Fatalf("Read error: %v", err)
			}

			var m map[string]any
			if err := json.Unmarshal(msg, &m); err != nil {
				continue
			}

			if m["type"] == "report" && m["function_name"] == "@global" {
				reportsCount++
				t.Logf("Received global report #%d", reportsCount)
				
				data := m["data"].(map[string]any)
				vars := data["variables"].([]any)
				
				foundCount := 0
				for _, vAny := range vars {
					v := vAny.(map[string]any)
					name := v["name"].(string)
					
					switch name {
					case "runtime.allp":
						foundCount++
						t.Logf("  - runtime.allp: %v", v["value"])
					case "runtime.allgs":
						foundCount++
						t.Logf("  - runtime.allgs: %v", v["value"])
					case "runtime.sched":
						foundCount++
						t.Logf("  - runtime.sched: %v", v["value"])
					case "runtime.gomaxprocs":
						foundCount++
						t.Logf("  - runtime.gomaxprocs: %v", v["value"])
					case "runtime.ncpu":
						foundCount++
						t.Logf("  - runtime.ncpu: %v", v["value"])
					}
				}

				if foundCount < len(targetVars) {
					t.Errorf("Global report missing some variables, found only %d/%d", foundCount, len(targetVars))
				}
			}
		}
	}
	
	t.Log("Successfully verified all requested runtime globals in periodic reports")
}
