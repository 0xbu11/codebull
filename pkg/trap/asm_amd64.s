//go:build amd64
// +build amd64

#include "funcdata.h"
#include "textflag.h"

// func getg() uintptr
TEXT ·getg(SB), NOSPLIT, $0-8
    MOVQ (TLS), AX
    MOVQ AX, ret+0(FP)
    RET
