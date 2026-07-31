//go:build !go1.27

package server

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/0xbu11/codebull/pkg/codebull"
	"github.com/0xbu11/codebull/pkg/instrument"
)

// Removing a point that is already gone has to be distinguishable from a real
// failure. Without that, a client cannot make removal idempotent: every "not
// found" looks like a server error, so it either retries forever or reports a
// success it never verified. The extension took the second option, which is how
// a leaked duration pair could be reported as a successful unregister.
func TestClassifyErrorSeparatesNotFoundFromFailure(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		wantCode string
		wantHTTP int
	}{
		{
			name:     "point missing at line",
			err:      fmt.Errorf("point not found in main.hot at line 37: %w", instrument.ErrNotFound),
			wantCode: ErrCodeNotFound,
			wantHTTP: http.StatusNotFound,
		},
		{
			name:     "duration point missing",
			err:      fmt.Errorf("duration point not found in main.hot at line 37: %w", instrument.ErrNotFound),
			wantCode: ErrCodeNotFound,
			wantHTTP: http.StatusNotFound,
		},
		{
			name:     "function never instrumented",
			err:      fmt.Errorf("function main.hot not instrumented: %w", instrument.ErrNotFound),
			wantCode: ErrCodeNotFound,
			wantHTTP: http.StatusNotFound,
		},
		{
			name:     "copy limit still reported as its own code",
			err:      codebull.ErrCopyFunctionLimitExceeded,
			wantCode: ErrCodeCopyLimitExceeded,
			wantHTTP: http.StatusTooManyRequests,
		},
		{
			name:     "anything else stays a server error",
			err:      fmt.Errorf("failed to patch module: permission denied"),
			wantCode: "",
			wantHTTP: http.StatusInternalServerError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, status := classifyError(tc.err)
			if code != tc.wantCode || status != tc.wantHTTP {
				t.Fatalf("classifyError(%v) = (%q, %d), want (%q, %d)",
					tc.err, code, status, tc.wantCode, tc.wantHTTP)
			}
		})
	}
}
