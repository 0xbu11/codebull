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

type Process struct {
	Cmd    *exec.Cmd
	Stderr io.ReadCloser
	Stdout io.ReadCloser
	Panic  string
	mu     sync.Mutex
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
		Cmd:    cmd,
		Stdout: stdout,
		Stderr: stderr,
	}
	
	go p.monitorStderr()
	
	return p, nil
}

func (p *Process) monitorStderr() {
	scanner := bufio.NewScanner(p.Stderr)
	var sb strings.Builder
	recording := false
	
	for scanner.Scan() {
		line := scanner.Text()
		fmt.Fprintln(os.Stderr, "[Target Stderr]", line)
		
		if strings.Contains(line, "panic:") || strings.Contains(line, "fatal error:") {
			recording = true
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

func (p *Process) Wait() error {
	return p.Cmd.Wait()
}
