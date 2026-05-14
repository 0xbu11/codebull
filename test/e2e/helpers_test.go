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
