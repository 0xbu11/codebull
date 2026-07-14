package framework

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

var crashMarkers = []string{
	"SIGSEGV",
	"SIGBUS",
	"SIGABRT",
	"panic:",
	"fatal error:",
	"runtime: ", // e.g. "runtime: bad pointer in frame ...", "runtime: unexpected return pc"
	"unexpected fault address",
	"invalid memory address or nil pointer dereference",
	"bad pointer in frame",
	"invalid pointer found on stack",
	"unknown caller pc",
	"traceback: unexpected",
}

func lineIsCrashMarker(line string) bool {
	for _, m := range crashMarkers {
		if strings.Contains(line, m) {
			return true
		}
	}
	return false
}

type Process struct {
	Cmd    *exec.Cmd
	Stderr io.ReadCloser
	Stdout io.ReadCloser
	Panic  string

	mu        sync.Mutex
	crashed   bool
	crashLine string        // the first crash marker line (a concise signature)
	crashCh   chan struct{} // closed exactly once when the first crash marker is seen
	closeOnce sync.Once
}

func RunBinary(ctx context.Context, binPath string, env []string) (*Process, error) {
	return RunBinaryWithCwd(ctx, binPath, env, "")
}

func RunBinaryWithCwd(ctx context.Context, binPath string, env []string, cwd string) (*Process, error) {
	cmd := exec.CommandContext(ctx, binPath)
	cmd.Env = append(os.Environ(), env...)
	if cwd != "" {
		cmd.Dir = cwd
	}

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	p := &Process{
		Cmd:     cmd,
		Stdout:  stdout,
		Stderr:  stderr,
		crashCh: make(chan struct{}),
	}

	go p.monitorStderr()

	return p, nil
}

func (p *Process) monitorStderr() {
	scanner := bufio.NewScanner(p.Stderr)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)

	echo := os.Getenv("EGO_SHADOW_E2E_ECHO") != ""

	var sb strings.Builder
	recording := false

	for scanner.Scan() {
		line := scanner.Text()
		if echo {
			fmt.Fprintln(os.Stderr, "[Target Stderr]", line)
		}

		if !recording && lineIsCrashMarker(line) {
			recording = true
			p.mu.Lock()
			if !p.crashed {
				p.crashed = true
				p.crashLine = strings.TrimSpace(line)
			}
			p.mu.Unlock()
			p.closeOnce.Do(func() { close(p.crashCh) })
		}

		if recording {
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}

	p.mu.Lock()
	p.Panic = sb.String()
	p.mu.Unlock()
}

func (p *Process) GetPanic() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Panic
}

func (p *Process) Crashed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.crashed
}

func (p *Process) CrashSignature() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.crashLine
}

func (p *Process) CrashReport() string {
	return p.GetPanic()
}

func (p *Process) CrashChan() <-chan struct{} {
	return p.crashCh
}

func (p *Process) Wait() error {
	return p.Cmd.Wait()
}
