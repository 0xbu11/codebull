package e2e

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/0xbu11/codebull/test/e2e/framework"
)

func TestPanicAnalysis(t *testing.T) {
	fixtures := []struct {
		name string
		path string
		function string
		line int
		vars []string
		rateLimit *framework.RateLimitConfig
	}{
		{
			name: "GC Stress",
			path: "./fixtures/gc_stress/main.go",
			function: "main.Work",
			line: 15,
			vars: []string{"id", "data", "s"},
		},
		{
			name: "Stack Growth",
			path: "./fixtures/stack_growth/main.go",
			function: "main.DeepWork",
			line: 15,
			vars: []string{"depth", "salt", "buffer"},
		},
		{
			name: "Preemption",
			path: "./fixtures/preemption/main.go",
			function: "main.TightLoop",
			line: 16,
			vars: []string{"sum", "i"},
			rateLimit: &framework.RateLimitConfig{
				Algorithm: "token_bucket",
				Rate:      1000000,
				Burst:     1000000,
			},
		},
	}

	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			binPath, err := framework.BuildFixture(tc.path)
			if err != nil {
				t.Fatalf("failed to build %s: %v", tc.name, err)
			}
			defer os.Remove(binPath)

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			addr := ln.Addr().String()
			ln.Close()

			env := []string{fmt.Sprintf("EGO_SHADOW_ADDR=%s", addr), "EGO_SHADOW_DEBUG=1", "EGO_SHADOW_ALLOW_RECURSIVE=1"}
			p, err := framework.RunBinary(ctx, binPath, env)
			if err != nil {
				t.Fatalf("failed to run %s: %v", tc.name, err)
			}

			time.Sleep(2 * time.Second)

			client := framework.NewClient(addr)
			err = client.AddTracepoint(framework.TraceRequest{
				Pattern: tc.function,
				Line: tc.line,
				VariableNames: tc.vars,
				RateLimit: tc.rateLimit,
			})
			if err != nil {
				t.Errorf("failed to instrument %s: %v", tc.name, err)
			}

			done := make(chan error)
			go func() {
				done <- p.Wait()
			}()

			select {
			case err := <-done:
				if p.GetPanic() != "" {
					t.Errorf("PANIC DETECTED in %s:\n%s", tc.name, p.GetPanic())
				} else if err != nil {
					t.Logf("Process exited with error: %v", err)
				}
			case <-time.After(15 * time.Second):
				t.Logf("Success: %s ran for 15s without crashing", tc.name)
				p.Cmd.Process.Kill()
			}
		})
	}
}
