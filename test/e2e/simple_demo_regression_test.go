//go:build !go1.23

package e2e_test

import (
	"bytes"
	"math"
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

func TestSimpleDemo_SPRegression(t *testing.T) {
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

	simpleDemoBin := filepath.Join(rootDir, "simple_demo_bin_e2e")
	buildCmd := exec.Command(
		"go", "build",
		"-gcflags", "all=-N -l -dwarflocationlists=true",
		"-ldflags", "-w=0 -s=0 -compressdwarf=false",
		"-o", simpleDemoBin,
		"./cmd/simple_demo",
	)
	buildCmd.Dir = rootDir
	var buildOut bytes.Buffer
	buildCmd.Stdout = &buildOut
	buildCmd.Stderr = &buildOut
	if err := buildCmd.Run(); err != nil {
		t.Fatalf("Failed to build cmd/simple_demo: %v\nOutput:\n%s", err, buildOut.String())
	}
	defer os.Remove(simpleDemoBin)

	srcFile := filepath.Join(rootDir, "cmd", "simple_demo", "simple_demo.go")
	targetLine := findLineContaining(t, srcFile, "return 1 + int(i8)")
	addr, err := findAddressForLine(simpleDemoBin, "cmd/simple_demo/simple_demo.go", targetLine)
	if err != nil {
		t.Fatalf("Failed to find address for line %d: %v", targetLine, err)
	}

	listenAddr := freeLocalAddr(t)
	demoCmd := exec.Command(simpleDemoBin)
	demoCmd.Env = append(os.Environ(), "EGO_SHADOW_ADDR="+listenAddr)
	var demoOut bytes.Buffer
	demoCmd.Stdout = &demoOut
	demoCmd.Stderr = &demoOut
	if err := demoCmd.Start(); err != nil {
		t.Fatalf("Failed to start simple_demo: %v", err)
	}
	defer func() {
		if demoCmd.Process != nil {
			_ = demoCmd.Process.Kill()
		}
	}()

	waitForHealth(t, "http://"+listenAddr+"/health", 5*time.Second)

	u := url.URL{Scheme: "ws", Host: listenAddr, Path: "/ws"}
	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer ws.Close()

	req := server.Request{
		Action: server.ActionRegister,
		Point: instrument.Point{
			Function: &function.Function{Name: "main.target"},
			Line:     targetLine,
			Address:  addr,
			Types:    []instrument.InstrumentType{instrument.Logging},
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

	ws.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		var msg map[string]any
		if err := ws.ReadJSON(&msg); err != nil {
			t.Fatalf("ReadJSON error: %v\n--- demo output ---\n%s", err, demoOut.String())
		}

		funcName, _ := msg["function_name"].(string)
		if funcName != "main.target" {
			continue
		}

		varsAny, ok := msg["variables"].([]any)
		if !ok {
			t.Fatalf("unexpected variables payload: %T", msg["variables"])
		}

		x := mustReadIntVar(t, varsAny, "x")
		if x < 1 || x > 100 {
			t.Fatalf("unexpected x=%d (expected 1..100). vars=%s", x, compactVars(varsAny))
		}

		b := mustReadBoolVar(t, varsAny, "b")
		if b != (x%2 == 0) {
			t.Fatalf("unexpected b=%v (expected %v). vars=%s", b, x%2 == 0, compactVars(varsAny))
		}

		i8 := mustReadIntVar(t, varsAny, "i8")
		if i8 != int64(int8(x)) {
			t.Fatalf("unexpected i8=%d (expected %d). vars=%s", i8, int64(int8(x)), compactVars(varsAny))
		}
		i16 := mustReadIntVar(t, varsAny, "i16")
		if i16 != int64(int16(x*2)) {
			t.Fatalf("unexpected i16=%d (expected %d). vars=%s", i16, int64(int16(x*2)), compactVars(varsAny))
		}
		i32 := mustReadIntVar(t, varsAny, "i32")
		if i32 != int64(int32(x*3)) {
			t.Fatalf("unexpected i32=%d (expected %d). vars=%s", i32, int64(int32(x*3)), compactVars(varsAny))
		}

		i64 := mustReadIntVar(t, varsAny, "i64")
		if i64 != x*4 {
			t.Fatalf("unexpected i64=%d (expected x*4=%d). vars=%s", i64, x*4, compactVars(varsAny))
		}

		u := mustReadIntVar(t, varsAny, "u")
		if u != x {
			t.Fatalf("unexpected u=%d (expected %d). vars=%s", u, x, compactVars(varsAny))
		}

		u64 := mustReadIntVar(t, varsAny, "u64")
		if u64 != x*10 {
			t.Fatalf("unexpected u64=%d (expected x*10=%d). vars=%s", u64, x*10, compactVars(varsAny))
		}

		f32 := mustReadFloatVar(t, varsAny, "f32")
		expF32 := float64(float32(x) + 0.25)
		if math.Abs(f32-expF32) > 1e-6 {
			t.Fatalf("unexpected f32=%g (expected %g). vars=%s", f32, expF32, compactVars(varsAny))
		}

		f64 := mustReadFloatVar(t, varsAny, "f64")
		expF64 := float64(x) + 0.5
		if math.Abs(f64-expF64) > 1e-12 {
			t.Fatalf("unexpected f64=%g (expected %g). vars=%s", f64, expF64, compactVars(varsAny))
		}

		re, im := mustReadComplexVar(t, varsAny, "c128")
		expRe := float64(x)
		expIm := float64(x + 1)
		if math.Abs(re-expRe) > 1e-12 || math.Abs(im-expIm) > 1e-12 {
			t.Fatalf("unexpected c128=(%g,%g) (expected %g,%g). vars=%s", re, im, expRe, expIm, compactVars(varsAny))
		}

		s := mustReadStringVar(t, varsAny, "s")
		if s != "hello" {
			t.Fatalf("unexpected s=%q (expected %q). vars=%s", s, "hello", compactVars(varsAny))
		}

		arrVar := mustFindVarMap(t, varsAny, "arr")
		if _, ok := arrVar["children"]; !ok {
			t.Fatalf("arr has no children; arr=%v vars=%s\n--- demo output ---\n%s", arrVar, compactVars(varsAny), demoOut.String())
		}
		arr0 := mustReadChildIntVar(t, arrVar, "[0]")
		arr3 := mustReadChildIntVar(t, arrVar, "[3]")
		if arr0 != x || arr3 != x+3 {
			t.Fatalf("unexpected arr=[%d,..,%d] (expected [%d,..,%d]). vars=%s\n--- demo output ---\n%s", arr0, arr3, x, x+3, compactVars(varsAny), demoOut.String())
		}

		slVar := mustFindVarMap(t, varsAny, "sl")
		if _, ok := slVar["children"]; !ok {
			t.Fatalf("sl has no children; sl=%v vars=%s\n--- demo output ---\n%s", slVar, compactVars(varsAny), demoOut.String())
		}
		sl0 := mustReadChildIntVar(t, slVar, "[0]")
		sl1 := mustReadChildIntVar(t, slVar, "[1]")
		sl2 := mustReadChildIntVar(t, slVar, "[2]")
		if sl0 != x || sl1 != x*2 || sl2 != x*3 {
			t.Fatalf("unexpected sl=[%d,%d,%d] (expected [%d,%d,%d]). vars=%s\n--- demo output ---\n%s", sl0, sl1, sl2, x, x*2, x*3, compactVars(varsAny), demoOut.String())
		}

		innerVar := mustFindVarMap(t, varsAny, "inner")
		if _, ok := innerVar["children"]; !ok {
			t.Fatalf("inner has no children; inner=%v vars=%s\n--- demo output ---\n%s", innerVar, compactVars(varsAny), demoOut.String())
		}
		innerA := mustReadChildIntVar(t, innerVar, "A")
		innerB := mustReadChildStringVar(t, innerVar, "B")
		innerC := mustFindChildMap(t, innerVar, "C")
		if _, ok := innerC["children"]; !ok {
			t.Fatalf("inner.C has no children; innerC=%v vars=%s\n--- demo output ---\n%s", innerC, compactVars(varsAny), demoOut.String())
		}
		c0 := mustReadChildIntVar(t, innerC, "[0]")
		c2 := mustReadChildIntVar(t, innerC, "[2]")
		if innerA != x*7 || innerB != "bee" || c0 != x || c2 != 3 {
			t.Fatalf("unexpected inner (A=%d B=%q C0=%d C2=%d). vars=%s\n--- demo output ---\n%s", innerA, innerB, c0, c2, compactVars(varsAny), demoOut.String())
		}

		return
	}
}

func compactVars(vars []any) string {
	parts := make([]string, 0, len(vars))
	for _, v := range vars {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		n, _ := m["name"].(string)
		val, _ := m["value"].(string)
		if n == "" {
			continue
		}
		parts = append(parts, n+"="+val)
	}
	return strings.Join(parts, ",")
}

func mustReadIntVar(t *testing.T, vars []any, name string) int64 {
	t.Helper()
	for _, v := range vars {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		vn, _ := m["name"].(string)
		if vn != name {
			continue
		}
		valStr, _ := m["value"].(string)
		if valStr == "" {
			t.Fatalf("variable %q has empty value (raw=%v)", name, m)
		}
		if len(valStr) >= 7 && valStr[:7] == "<Error:" {
			t.Fatalf("variable %q unreadable: %s", name, valStr)
		}
		val, err := strconv.ParseInt(valStr, 10, 64)
		if err != nil {
			t.Fatalf("variable %q parse int failed for %q: %v", name, valStr, err)
		}
		return val
	}

	t.Fatalf("variable %q not found in trace vars (len=%d)", name, len(vars))
	return 0
}

func mustFindVarMap(t *testing.T, vars []any, name string) map[string]any {
	t.Helper()
	for _, v := range vars {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		vn, _ := m["name"].(string)
		if vn == name {
			return m
		}
	}
	t.Fatalf("variable %q not found in trace vars (len=%d)", name, len(vars))
	return nil
}

func mustFindChildMap(t *testing.T, parent map[string]any, childName string) map[string]any {
	t.Helper()
	children, _ := parent["children"].([]any)
	names := make([]string, 0, len(children))
	for _, c := range children {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		n, _ := cm["name"].(string)
		if n != "" {
			names = append(names, n)
		}
		if n == childName {
			return cm
		}
	}
	t.Fatalf("child %q not found under %q; available=%v; parent=%v", childName, parent["name"], names, parent)
	return nil
}

func mustReadStringVar(t *testing.T, vars []any, name string) string {
	t.Helper()
	for _, v := range vars {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		vn, _ := m["name"].(string)
		if vn != name {
			continue
		}
		valStr, _ := m["value"].(string)
		if valStr == "" {
			t.Fatalf("variable %q has empty value (raw=%v)", name, m)
		}
		if len(valStr) >= 7 && valStr[:7] == "<Error:" {
			t.Fatalf("variable %q unreadable: %s", name, valStr)
		}
		return valStr
	}
	t.Fatalf("variable %q not found in trace vars (len=%d)", name, len(vars))
	return ""
}

func mustReadChildIntVar(t *testing.T, parent map[string]any, childName string) int64 {
	t.Helper()
	child := mustFindChildMap(t, parent, childName)
	valStr, _ := child["value"].(string)
	if valStr == "" {
		t.Fatalf("child %q has empty value (raw=%v)", childName, child)
	}
	if len(valStr) >= 7 && valStr[:7] == "<Error:" {
		t.Fatalf("child %q unreadable: %s", childName, valStr)
	}
	val, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil {
		t.Fatalf("child %q parse int failed for %q: %v", childName, valStr, err)
	}
	return val
}

func mustReadChildStringVar(t *testing.T, parent map[string]any, childName string) string {
	t.Helper()
	child := mustFindChildMap(t, parent, childName)
	valStr, _ := child["value"].(string)
	if valStr == "" {
		t.Fatalf("child %q has empty value (raw=%v)", childName, child)
	}
	if len(valStr) >= 7 && valStr[:7] == "<Error:" {
		t.Fatalf("child %q unreadable: %s", childName, valStr)
	}
	return valStr
}

func mustReadBoolVar(t *testing.T, vars []any, name string) bool {
	t.Helper()
	for _, v := range vars {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		vn, _ := m["name"].(string)
		if vn != name {
			continue
		}
		valStr, _ := m["value"].(string)
		if valStr == "" {
			t.Fatalf("variable %q has empty value (raw=%v)", name, m)
		}
		if len(valStr) >= 7 && valStr[:7] == "<Error:" {
			t.Fatalf("variable %q unreadable: %s", name, valStr)
		}
		val, err := strconv.ParseBool(valStr)
		if err != nil {
			t.Fatalf("variable %q parse bool failed for %q: %v", name, valStr, err)
		}
		return val
	}
	t.Fatalf("variable %q not found in trace vars (len=%d)", name, len(vars))
	return false
}

func mustReadFloatVar(t *testing.T, vars []any, name string) float64 {
	t.Helper()
	for _, v := range vars {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		vn, _ := m["name"].(string)
		if vn != name {
			continue
		}
		valStr, _ := m["value"].(string)
		if valStr == "" {
			t.Fatalf("variable %q has empty value (raw=%v)", name, m)
		}
		if len(valStr) >= 7 && valStr[:7] == "<Error:" {
			t.Fatalf("variable %q unreadable: %s", name, valStr)
		}
		val, err := strconv.ParseFloat(valStr, 64)
		if err != nil {
			t.Fatalf("variable %q parse float failed for %q: %v", name, valStr, err)
		}
		return val
	}
	t.Fatalf("variable %q not found in trace vars (len=%d)", name, len(vars))
	return 0
}

func mustReadComplexVar(t *testing.T, vars []any, name string) (float64, float64) {
	t.Helper()
	for _, v := range vars {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		vn, _ := m["name"].(string)
		if vn != name {
			continue
		}
		valStr, _ := m["value"].(string)
		if valStr == "" {
			t.Fatalf("variable %q has empty value (raw=%v)", name, m)
		}
		if len(valStr) >= 7 && valStr[:7] == "<Error:" {
			t.Fatalf("variable %q unreadable: %s", name, valStr)
		}
		valStr = strings.TrimSpace(valStr)
		valStr = strings.TrimPrefix(valStr, "(")
		valStr = strings.TrimSuffix(valStr, ")")
		valStr = strings.TrimSuffix(valStr, "i")

		split := -1
		for i := 1; i < len(valStr); i++ {
			c := valStr[i]
			if c != '+' && c != '-' {
				continue
			}
			prev := valStr[i-1]
			if prev == 'e' || prev == 'E' {
				continue
			}
			split = i
		}
		if split == -1 {
			t.Fatalf("variable %q parse complex failed for %q", name, valStr)
		}

		reStr := valStr[:split]
		imStr := valStr[split:]
		re, err := strconv.ParseFloat(reStr, 64)
		if err != nil {
			t.Fatalf("variable %q parse complex real failed for %q: %v", name, reStr, err)
		}
		im, err := strconv.ParseFloat(imStr, 64)
		if err != nil {
			t.Fatalf("variable %q parse complex imag failed for %q: %v", name, imStr, err)
		}
		return re, im
	}
	t.Fatalf("variable %q not found in trace vars (len=%d)", name, len(vars))
	return 0, 0
}
