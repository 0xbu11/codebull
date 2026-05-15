package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/0xbu11/codebull/pkg/function"
	"github.com/0xbu11/codebull/pkg/instrument"
	"github.com/0xbu11/codebull/pkg/server"
	"github.com/gorilla/websocket"
)

func TestVariableCoverage(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Only supported on Linux")
	}

	rootDir, _ := os.Getwd()
	for !containsGoMod(rootDir) {
		rootDir = filepath.Dir(rootDir)
	}

	fixtureBin := filepath.Join(os.TempDir(), "ego-shadow-coverage-test")
	
	buildCmd := exec.Command("go", "build",
		"-gcflags", "all=-N -l",
		"-ldflags", "-w=0 -s=0 -compressdwarf=false",
		"-o", fixtureBin,
		"./test/e2e/fixtures/coverage",
	)
	buildCmd.Dir = rootDir
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("Build failed: %v\nOutput: %s", err, string(out))
	}
	defer os.Remove(fixtureBin)

	listenAddr := freeLocalAddr(t)
	cmd := exec.Command(fixtureBin)
	cmd.Env = append(os.Environ(), "EGO_SHADOW_ADDR="+listenAddr, "EGO_SHADOW_DEBUG=1", "EGO_SHADOW_ALLOW_RECURSIVE=1")
	
	debugLog, _ := os.Create(filepath.Join(rootDir, "coverage_debug.log"))
	defer debugLog.Close()
	cmd.Stdout = debugLog
	cmd.Stderr = debugLog

	if err := cmd.Start(); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	defer cmd.Process.Kill()

	waitForHealth(t, "http://"+listenAddr+"/health", 5*time.Second)

	srcFile := filepath.Join(rootDir, "test", "e2e", "fixtures", "coverage", "main.go")
	targets := []struct {
		Label string
		Match string
	}{
		{"Entry", "b := (x > 0)"},
		{"AfterBasic", "arr := [2]int"},
		{"AfterComposite", "ptr := &st"},
		{"AfterComplex", "fmt.Println(\"AfterComplex\")"},
		{"InsideIf", "inner :="},
		{"InsideLoop", "loopVar :="},
		{"BeforeReturn", "return res"},
	}

	results := make(map[int][]any)

	for _, tcase := range targets {
		t.Run(tcase.Label, func(t *testing.T) {
			u := url.URL{Scheme: "ws", Host: listenAddr, Path: "/ws"}
			ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
			if err != nil {
				t.Fatalf("Dial failed: %v", err)
			}
			fmt.Printf("DEBUG: Subtest %s, ws=%p\n", tcase.Label, ws)
			defer ws.Close()

			line := findLineContaining(t, srcFile, tcase.Match)
			addr, err := findAddressForLine(fixtureBin, "test/e2e/fixtures/coverage/main.go", line)
			if err != nil {
				t.Skipf("Skipping line %d: %v", line, err)
			}

			req := server.Request{
				Action: server.ActionRegister,
				Point: instrument.Point{
					Function: &function.Function{Name: "main.CoverageTarget"},
					Line:     line,
					Address:  addr,
					Types:    []instrument.InstrumentType{instrument.Logging},
				},
			}
			if err := ws.WriteJSON(req); err != nil {
				t.Fatalf("Register failed: %v", err)
			}

			var resp server.Response
			fmt.Printf("DEBUG: Before Read register response\n")
			if err := ws.ReadJSON(&resp); err != nil {
				fmt.Printf("DEBUG: Read register response failed: %v\n", err)
				t.Fatalf("Read register response failed: %v", err)
			}
			fmt.Printf("DEBUG: After Read register response, resp=%+v\n", resp)
			if resp.Status == "error" {
				t.Fatalf("Register tracepoint failed: %s", resp.Message)
			}

			deadline := time.After(5 * time.Second)
			found := false
			connected := true
			for !found && connected {
				ws.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
				_, msg, err := ws.ReadMessage()
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						select {
						case <-deadline:
							t.Errorf("Timeout waiting for trace at line %d", line)
							return
						default:
						}
						continue
					}
					t.Errorf("ReadMessage failed at line %d: %v", line, err)
					return
				}

				var m map[string]any
				if err := json.Unmarshal(msg, &m); err != nil {
					continue
				}

				if m["type"] == "report" {
					data := m["data"].(map[string]any)
					vars := data["variables"].([]any)
					t.Logf("Subtest %s received %d variables", tcase.Label, len(vars))

					lineVal := fmt.Sprintf("%v", data["line"])
					var lineNum int
					fmt.Sscanf(lineVal, "%d", &lineNum)

					if lineNum == line {
						results[line] = data["variables"].([]any)
						found = true
					}
				}
			}

			if connected {
				unreq := server.Request{
					Action: server.ActionUnregister,
					Point:  instrument.Point{Address: addr},
				}
				ws.WriteJSON(unreq)
				ws.ReadJSON(&resp)
			}
		})
	}

	reportPath := filepath.Join(rootDir, "variable_coverage_report.md")
	f, _ := os.Create(reportPath)
	defer f.Close()

	fmt.Fprintln(f, "# Variable Coverage Analysis Report")
	fmt.Fprintf(f, "\nGenerated at: %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintln(f, "\n## Results by Line")
	fmt.Fprintln(f, "| Line | Total Vars | Readable | Unreadable | Details |")
	fmt.Fprintln(f, "|------|------------|----------|------------|---------|")

	sortedLines := sortKeys(results)
	for _, line := range sortedLines {
		vars := results[line]
		readable := 0
		unreadable := 0
		var errs []string

		for _, v := range vars {
			m := v.(map[string]any)
			if m["unreadable"] != nil && m["unreadable"] != "" {
				unreadable++
				errs = append(errs, fmt.Sprintf("%s: %v", m["name"], m["unreadable"]))
			} else {
				readable++
			}
		}

		errStr := "-"
		if len(errs) > 0 {
			errStr = strings.Join(errs, "; ")
			if len(errStr) > 50 {
				errStr = errStr[:47] + "..."
			}
		}

		fmt.Fprintf(f, "| %d | %d | %d | %d | %s |\n", line, len(vars), readable, unreadable, errStr)
	}

	fmt.Fprintln(f, "\n## Type Effectiveness Analysis")
	fmt.Fprintln(f, "| Type | Status | Observations |")
	fmt.Fprintln(f, "|------|--------|--------------|")
	
	typeStats := checkTypeEffectiveness(results)
	for _, tname := range []string{"int", "int8", "float32", "complex64", "bool", "struct string", "struct []int", "[2]int", "main.smallStruct", "main.complexStruct", "*main.smallStruct", "map[string]int", "interface {}"} {
		stat := typeStats[tname]
		fmt.Fprintf(f, "| %s | %s | %s |\n", tname, stat.Status, stat.Note)
	}

	t.Logf("Report generated at %s", reportPath)
}

func checkTypeEffectiveness(results map[int][]any) map[string]typeStat {
	stats := make(map[string]typeStat)
	targetTypes := []string{"int", "int8", "float32", "complex64", "bool", "struct string", "struct []int", "[2]int", "main.smallStruct", "main.complexStruct", "*main.smallStruct", "map[string]int", "interface {}"}
	
	for _, tname := range targetTypes {
		stats[tname] = typeStat{Status: "Not found", Note: "No trace data"}
	}

	for _, vars := range results {
		for _, v := range vars {
			m := v.(map[string]any)
			vt := m["type"].(string)
			if stat, ok := stats[vt]; ok {
				unreadable := m["unreadable"] != nil && m["unreadable"] != ""
				if unreadable {
					if stat.Status != "Success" {
						stats[vt] = typeStat{Status: "Partial/Fail", Note: fmt.Sprintf("Failed: %v", m["unreadable"])}
					}
				} else {
					note := "Correctly extracted"
					if strings.Contains(vt, "[]int") || strings.Contains(vt, "[2]int") {
						children, _ := m["children"].([]any)
						if len(children) > 0 {
							var vals []string
							for i := 0; i < len(children) && i < 2; i++ {
								child := children[i].(map[string]any)
								vals = append(vals, fmt.Sprintf("%v", child["value"]))
							}
							note = fmt.Sprintf("Extracted values: [%s]", strings.Join(vals, ", "))
							if len(children) > 2 {
								note += "..."
							}
						} else {
							note = "Success (Empty or children not loaded)"
						}
					}
					stats[vt] = typeStat{Status: "Success", Note: note}
				}
			}
		}
	}
	return stats
}

type typeStat struct {
	Status string
	Note   string
}



func sortKeys(m map[int][]any) []int {
	var keys []int
	for k := range m {
		keys = append(keys, k)
	}
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	return keys
}
