package framework

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

type InstrumentSpec struct {
	FixturePath   string   // e.g. "./fixtures/gc_stress/main.go"
	Function      string   // e.g. "main.Work"
	Line          int      // 1-based source line
	VariableNames []string // variables to capture (optional)
	RateLimit     *RateLimitConfig
}

func freeLoopbackAddr() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "127.0.0.1:0"
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func RunInstrumentedFixture(t testing.TB, spec InstrumentSpec, window time.Duration) (crashed bool, report string) {
	t.Helper()

	binPath, err := BuildFixture(spec.FixturePath)
	if err != nil {
		t.Fatalf("build %s: %v", spec.FixturePath, err)
	}
	t.Cleanup(func() { _ = os.Remove(binPath) })

	ctx, cancel := context.WithTimeout(context.Background(), window+20*time.Second)
	t.Cleanup(cancel)

	addr := freeLoopbackAddr()
	env := []string{
		"EGO_SHADOW_ADDR=" + addr,
		"EGO_SHADOW_ALLOW_RECURSIVE=1",
	}
	p, err := RunBinary(ctx, binPath, env)
	if err != nil {
		t.Fatalf("run %s: %v", spec.FixturePath, err)
	}
	t.Cleanup(func() {
		if p.Cmd.Process != nil {
			_ = p.Cmd.Process.Kill()
		}
	})

	time.Sleep(2 * time.Second)

	if err := NewClient(addr).AddTracepoint(TraceRequest{
		Pattern:       spec.Function,
		Line:          spec.Line,
		VariableNames: spec.VariableNames,
		RateLimit:     spec.RateLimit,
	}); err != nil {
		t.Fatalf("instrument %s:%d: %v", spec.Function, spec.Line, err)
	}

	exited := make(chan struct{})
	go func() { _ = p.Wait(); close(exited) }()

	select {
	case <-p.CrashChan():
		crashed = true
	case <-exited:
		crashed = p.Crashed()
	case <-time.After(window):
		crashed = p.Crashed()
	}

	if crashed {
		time.Sleep(300 * time.Millisecond)
	}
	return crashed, p.CrashReport()
}

func AssertNoCrashUnderInstrumentation(t testing.TB, spec InstrumentSpec, window time.Duration) {
	t.Helper()
	crashed, report := RunInstrumentedFixture(t, spec, window)
	if crashed {
		t.Fatalf("target crashed under instrumentation of %s:%d within %s\n--- crash report ---\n%s",
			spec.Function, spec.Line, window, report)
	}
	t.Logf("survived %s under instrumentation of %s:%d", window, spec.Function, spec.Line)
}
