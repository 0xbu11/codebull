//go:build arm64
// +build arm64

#include "funcdata.h"
#include "textflag.h"

// func getContext() uintptr
TEXT ·getContext(SB), NOSPLIT, $0-8
    // In our future trampoline, we must save the context pointer to R19
    // before calling Callback, matching this expectation.
    MOVD R19, ret+0(FP)
    RET

// func getg() uintptr
TEXT ·getg(SB), NOSPLIT, $0-8
    MOVD (TLS), R0
    MOVD R0, ret+0(FP)
    RET
