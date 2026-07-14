package e2e

import (
	"testing"
	"time"

	"github.com/0xbu11/codebull/test/e2e/framework"
)

func TestPanicAnalysis(t *testing.T) {
	fixtures := []struct {
		name string
		spec framework.InstrumentSpec
	}{
		{
			name: "GC Stress",
			spec: framework.InstrumentSpec{
				FixturePath:   "./fixtures/gc_stress/main.go",
				Function:      "main.Work",
				Line:          15,
				VariableNames: []string{"id", "data", "s"},
			},
		},
		{
			name: "Stack Growth",
			spec: framework.InstrumentSpec{
				FixturePath:   "./fixtures/stack_growth/main.go",
				Function:      "main.DeepWork",
				Line:          15,
				VariableNames: []string{"depth", "salt", "buffer"},
			},
		},
		{
			name: "Preemption",
			spec: framework.InstrumentSpec{
				FixturePath:   "./fixtures/preemption/main.go",
				Function:      "main.TightLoop",
				Line:          16,
				VariableNames: []string{"sum", "i"},
				RateLimit: &framework.RateLimitConfig{
					Algorithm: "token_bucket",
					Rate:      1000000,
					Burst:     1000000,
				},
			},
		},
	}

	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			framework.AssertNoCrashUnderInstrumentation(t, tc.spec, 15*time.Second)
		})
	}
}
