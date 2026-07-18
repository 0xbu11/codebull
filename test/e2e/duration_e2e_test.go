//go:build !go1.27

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestDurationE2E(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Only supported on Linux")
	}

	rootDir, _ := os.Getwd()
	for !containsGoMod(rootDir) {
		rootDir = filepath.Dir(rootDir)
	}

	fixtureSrc := filepath.Join(rootDir, "test", "e2e", "fixtures", "duration", "main.go")
	entryLine := findLineContaining(t, fixtureSrc, "// duration-entry")
	exitLine := findLineContaining(t, fixtureSrc, "// duration-exit")

	fixtureBin := filepath.Join(os.TempDir(), "ego-shadow-duration-test")
	buildCmd := exec.Command("go", "build",
		"-gcflags", "all=-N -l",
		"-ldflags", "-w=0 -s=0 -compressdwarf=false",
		"-o", fixtureBin,
		"./test/e2e/fixtures/duration",
	)
	buildCmd.Dir = rootDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Build failed: %v\nOutput: %s", err, string(out))
	}
	defer os.Remove(fixtureBin)

	listenAddr := freeLocalAddr(t)
	cmd := exec.Command(fixtureBin)
	cmd.Env = append(os.Environ(), "EGO_SHADOW_ADDR="+listenAddr)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer cmd.Process.Kill()

	base := "http://" + listenAddr
	waitForHealth(t, base+"/health", 5*time.Second)

	healthResp, err := http.Get(base + "/health")
	if err != nil {
		t.Fatalf("health: %v", err)
	}
	var health map[string]any
	if err := json.NewDecoder(healthResp.Body).Decode(&health); err != nil {
		t.Fatalf("decode health: %v", err)
	}
	healthResp.Body.Close()
	if avail, _ := health["duration_available"].(bool); !avail {
		t.Fatalf("duration_available = false in /health: %v", health)
	}

	u := url.URL{Scheme: "ws", Host: listenAddr, Path: "/ws"}
	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	defer ws.Close()

	registerURL := fmt.Sprintf("%s/trace?pattern=main.work&line=%d&type=duration&end_line=%d",
		base, entryLine, exitLine)
	resp, err := http.Get(registerURL)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	var regBody map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&regBody); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || regBody["status"] != "ok" {
		t.Fatalf("register failed: HTTP %d %v", resp.StatusCode, regBody)
	}

	ws.SetReadDeadline(time.Now().Add(15 * time.Second))
	var durationNs int64
	var goid int64
	for {
		var msg map[string]any
		if err := ws.ReadJSON(&msg); err != nil {
			t.Fatalf("no duration report received: %v", err)
		}
		if msg["type"] != "report" {
			continue
		}
		data, _ := msg["data"].(map[string]any)
		if data == nil || data["function_name"] != "main.work" {
			continue
		}
		vars, _ := data["variables"].([]any)
		if len(vars) == 0 {
			continue
		}
		found := false
		for _, vAny := range vars {
			v, _ := vAny.(map[string]any)
			name, _ := v["name"].(string)
			valStr, _ := v["value"].(string)
			switch name {
			case "__duration_ns":
				durationNs, err = strconv.ParseInt(valStr, 10, 64)
				if err != nil {
					t.Fatalf("__duration_ns not an integer: %q", valStr)
				}
				found = true
			case "__goid":
				goid, _ = strconv.ParseInt(valStr, 10, 64)
			}
		}
		if !found {
			continue
		}
		if line, _ := data["line"].(float64); int(line) != entryLine {
			t.Fatalf("report line = %v, want %d", data["line"], entryLine)
		}
		break
	}

	if durationNs < int64(5*time.Millisecond) {
		t.Fatalf("__duration_ns = %d, want >= 5ms", durationNs)
	}
	if goid <= 0 {
		t.Fatalf("__goid = %d, want > 0", goid)
	}
	t.Logf("sample: goid=%d duration=%.3fms", goid, float64(durationNs)/1e6)

	statusURL := fmt.Sprintf("%s/trace/status?pattern=main.work&line=%d", base, entryLine)
	resp, err = http.Get(statusURL)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	var status map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	resp.Body.Close()
	if inst, _ := status["instrumented"].(bool); !inst {
		t.Fatalf("status says not instrumented: %v", status)
	}
	if el, _ := status["end_line"].(float64); int(el) != exitLine {
		t.Fatalf("status end_line = %v, want %d", status["end_line"], exitLine)
	}
	dur, _ := status["duration"].(map[string]any)
	if dur == nil {
		t.Fatalf("status missing duration block: %v", status)
	}
	if completed, _ := dur["completed"].(float64); completed < 1 {
		t.Fatalf("duration.completed = %v, want >= 1", dur["completed"])
	}
	t.Logf("duration status: %v", dur)

	deleteURL := fmt.Sprintf("%s/trace?pattern=main.work&line=%d&type=duration&end_line=%d",
		base, entryLine, exitLine)
	req, _ := http.NewRequest(http.MethodDelete, deleteURL, nil)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	var delBody map[string]any
	json.NewDecoder(resp.Body).Decode(&delBody)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || delBody["status"] != "ok" {
		t.Fatalf("delete failed: HTTP %d %v", resp.StatusCode, delBody)
	}

	resp, err = http.Get(statusURL)
	if err != nil {
		t.Fatalf("status after delete: %v", err)
	}
	status = map[string]any{}
	json.NewDecoder(resp.Body).Decode(&status)
	resp.Body.Close()
	if inst, _ := status["instrumented"].(bool); inst {
		t.Fatalf("still instrumented after delete: %v", status)
	}
}
