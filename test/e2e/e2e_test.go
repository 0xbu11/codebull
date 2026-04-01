//go:build !go1.23

package e2e_test

import (
	"bufio"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xbu11/codebull/pkg/function"
	"github.com/0xbu11/codebull/pkg/instrument"
	"github.com/0xbu11/codebull/pkg/server"
	"github.com/gorilla/websocket"
)

func TestE2E(t *testing.T) {
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

	demoSource := filepath.Join(rootDir, "demo", "demo.go")
	demoBin := filepath.Join(rootDir, "demo_bin_e2e")

	cmd := exec.Command("go", "build",
		"-gcflags", "-dwarflocationlists=true",
		"-ldflags", "-w=0 -s=0 -compressdwarf=false",
		"-o", demoBin,
		demoSource)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	t.Logf("Building demo: %s", cmd.String())
	if err := cmd.Run(); err != nil {
		t.Fatalf("Failed to build demo: %v", err)
	}
	defer os.Remove(demoBin)

	targetLine := findLineContaining(t, demoSource, "res += x")
	addr, err := findAddressForLine(demoBin, "demo/demo.go", targetLine)
	if err != nil {
		t.Fatalf("Failed to find address for line %d: %v", targetLine, err)
	}
	t.Logf("Found address for line %d: 0x%x", targetLine, addr)

	demoCmd := exec.Command(demoBin)
	listenAddr := freeLocalAddr(t)
	demoCmd.Env = append(os.Environ(), "EGO_SHADOW_ADDR="+listenAddr)

	if err := demoCmd.Start(); err != nil {
		t.Fatalf("Failed to start demo: %v", err)
	}
	defer func() {
		if demoCmd.Process != nil {
			demoCmd.Process.Kill()
		}
	}()

	waitForHealth(t, "http://"+listenAddr+"/health", 5*time.Second)

	u := url.URL{Scheme: "ws", Host: listenAddr, Path: "/ws"}
	var ws *websocket.Conn

	for i := 0; i < 20; i++ {
		ws, _, err = websocket.DefaultDialer.Dial(u.String(), nil)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("dial failed after retries: %v", err)
	}
	defer ws.Close()

	req := server.Request{
		Action: server.ActionRegister,
		Point: instrument.Point{
			File: "demo/demo.go", // Optional when registering by address.
			Function: &function.Function{
				Name: "main.target",
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
	t.Log("Registration successful")

	found := false
	ws.SetReadDeadline(time.Now().Add(10 * time.Second))

	for {
		var msg map[string]interface{}
		err := ws.ReadJSON(&msg)
		if err != nil {
			t.Fatalf("ReadJSON error: %v", err)
		}


		if funcName, ok := msg["function_name"].(string); ok && funcName == "main.target" {
			t.Logf("Received trace for main.target: %+v", msg)
			found = true
			break
		}
	}

	if !found {
		t.Fatal("Did not receive expected trace data")
	}
}

func findLineContaining(t *testing.T, filePath string, needle string) int {
	t.Helper()
	f, err := os.Open(filePath)
	if err != nil {
		t.Fatalf("failed to open %s: %v", filePath, err)
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	line := 0
	for s.Scan() {
		line++
		if strings.Contains(s.Text(), needle) {
			return line
		}
	}
	if err := s.Err(); err != nil {
		t.Fatalf("failed to scan %s: %v", filePath, err)
	}
	t.Fatalf("needle %q not found in %s", needle, filePath)
	return 0
}

func freeLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to pick free port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return "127.0.0.1:" + strconv.Itoa(port)
}

func waitForHealth(t *testing.T, url string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for health at %s", url)
		}
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func findAddressForLine(binPath, fileSuffix string, line int) (uint64, error) {
	f, err := elf.Open(binPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	dw, err := f.DWARF()
	if err != nil {
		return 0, err
	}

	r := dw.Reader()
	for {
		entry, err := r.Next()
		if err != nil {
			break
		}
		if entry == nil {
			break
		}

		if entry.Tag == dwarf.TagCompileUnit {
			lr, err := dw.LineReader(entry)
			if err != nil {
				continue
			}
			if lr == nil {
				continue
			}

			var lentry dwarf.LineEntry
			for {
				if err := lr.Next(&lentry); err != nil {
					if err == io.EOF {
						break
					}
					break
				}
				if lentry.Line == line {
					if strings.HasSuffix(lentry.File.Name, fileSuffix) {
						return lentry.Address, nil
					}
				}
			}
		}
	}

	return 0, fmt.Errorf("line %d not found in %s", line, fileSuffix)
}
