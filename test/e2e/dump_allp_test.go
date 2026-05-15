package e2e

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/0xbu11/codebull/pkg/function"
	"github.com/0xbu11/codebull/pkg/instrument"
	"github.com/0xbu11/codebull/pkg/server"
	"github.com/gorilla/websocket"
)

func TestDumpAllP(t *testing.T) {
	rootDir, _ := os.Getwd()
	for !containsGoMod(rootDir) {
		rootDir = filepath.Dir(rootDir)
	}

	fixtureBin := filepath.Join(os.TempDir(), "ego-shadow-dump-allp")

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

	addr, err := findFunctionAddress(fixtureBin, "main.useMap")
	if err != nil {
		t.Fatalf("Failed to find address: %v", err)
	}

	req := server.Request{
		Action: server.ActionRegister,
		Point: instrument.Point{
			Function:      &function.Function{Name: "main.useMap"},
			Address:       addr,
			VariableNames: []string{"runtime.allp"},
			Types:         []instrument.InstrumentType{instrument.Logging},
		},
	}
	if err := ws.WriteJSON(req); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
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
			vars := data["variables"].([]any)
			for _, vAny := range vars {
				v := vAny.(map[string]any)
				if v["name"] == "runtime.allp" {
					pretty, _ := json.MarshalIndent(v, "", "  ")
					fmt.Printf("\n--- DATA START ---\n%s\n--- DATA END ---\n", string(pretty))
					return
				}
			}
		}
	}
}
