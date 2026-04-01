//go:build !go1.23

package e2e_test

import (
	"bytes"
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

func TestDemo2_RecursiveForceMorestackPoint(t *testing.T) {
	rootDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get wd: %v", err)
	}
	if filepath.Base(rootDir) == "e2e" {
		rootDir = filepath.Dir(filepath.Dir(rootDir))
	}
	if filepath.Base(rootDir) == "test" {
		rootDir = filepath.Dir(rootDir)
	}

	demo2Source := filepath.Join(rootDir, "demo", "demo2.go")
	demo2Bin := filepath.Join(rootDir, "demo2_bin_e2e")
	buildCmd := exec.Command(
		"go", "build",
		"-gcflags", "all=-N -l -dwarflocationlists=true",
		"-ldflags", "-w=0 -s=0 -compressdwarf=false",
		"-o", demo2Bin,
		demo2Source,
	)
	buildCmd.Dir = rootDir
	var buildOut bytes.Buffer
	buildCmd.Stdout = &buildOut
	buildCmd.Stderr = &buildOut
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build demo2: %v\nOutput:\n%s", err, buildOut.String())
	}
	defer os.Remove(demo2Bin)

	targetLine := findLineContaining(t, demo2Source, "pad[0] = byte(depth)")
	addr, err := findAddressForLine(demo2Bin, "demo/demo2.go", targetLine)
	if err != nil {
		t.Fatalf("Failed to find address for line %d: %v", targetLine, err)
	}

	listenAddr := freeLocalAddr(t)
	demoCmd := exec.Command(demo2Bin)
	demoCmd.Env = append(os.Environ(), "EGO_SHADOW_ADDR="+listenAddr)
	var demoOut bytes.Buffer
	demoCmd.Stdout = &demoOut
	demoCmd.Stderr = &demoOut
	if err := demoCmd.Start(); err != nil {
		t.Fatalf("Failed to start demo2: %v", err)
	}
	defer func() {
		if demoCmd.Process != nil {
			_ = demoCmd.Process.Kill()
		}
	}()

	waitForHealth(t, "http://"+listenAddr+"/health", 6*time.Second)

	u := url.URL{Scheme: "ws", Host: listenAddr, Path: "/ws"}
	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	req := server.Request{
		Action: server.ActionRegister,
		Point: instrument.Point{
			File: "demo/demo2.go",
			Function: &function.Function{
				Name: "main.forceMorestack",
			},
			Line:    targetLine,
			Address: addr,
			Types:   []instrument.InstrumentType{instrument.Logging},
		},
	}
	if err := ws.WriteJSON(req); err != nil {
		t.Fatalf("write register: %v", err)
	}

	var resp server.Response
	if err := ws.ReadJSON(&resp); err != nil {
		t.Fatalf("read register response: %v", err)
	}
	if resp.Status != "success" {
		t.Fatalf("register failed: %v", resp.Message)
	}

	ws.SetReadDeadline(time.Now().Add(25 * time.Second))
	for {
		var msg map[string]any
		if err := ws.ReadJSON(&msg); err != nil {
			t.Fatalf("ReadJSON error: %v\n--- demo2 output ---\n%s", err, demoOut.String())
		}

		funcName, _ := msg["function_name"].(string)
		if funcName != "main.forceMorestack" {
			continue
		}

		varsAny, ok := msg["variables"].([]any)
		if !ok {
			t.Fatalf("unexpected variables payload: %T", msg["variables"])
		}

		depth := mustReadIntVar(t, varsAny, "depth")
		if depth < 0 || depth > 16 {
			t.Fatalf("unexpected depth=%d (expected 0..16). vars=%s", depth, compactVars(varsAny))
		}
		return
	}
}
