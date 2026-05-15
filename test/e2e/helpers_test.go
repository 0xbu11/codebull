package e2e

import (
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func containsGoMod(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "go.mod"))
	return err == nil
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

func findFunctionAddress(binPath, funcName string) (uint64, error) {
	f, err := elf.Open(binPath)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		return 0, err
	}

	for _, sym := range syms {
		if sym.Name == funcName {
			return sym.Value, nil
		}
	}

	return 0, fmt.Errorf("function %s not found in symbols", funcName)
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

func findLineContaining(t *testing.T, path, snippet string) int {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if strings.Contains(line, snippet) {
			return i + 1
		}
	}
	t.Fatalf("snippet %q not found in %s", snippet, path)
	return 0
}
