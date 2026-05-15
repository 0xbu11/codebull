package main

import (
	"fmt"
	"time"

	_ "github.com/0xbu11/codebull"
)

type smallStruct struct {
	A int
	B string
}

type complexStruct struct {
	S smallStruct
	P *smallStruct
	A [2]int
	L []string
	M map[string]int
}

//go:noinline
func CoverageTarget(x int, s string) int {
	fmt.Printf("CoverageTarget called with x=%d\n", x)
	b := (x > 0)
	i8 := int8(x)
	f32 := float32(x)
	c64 := complex(float32(x), 1.0)

	arr := [2]int{x, x + 1}
	sl := []int{x, x + 2}
	st := smallStruct{A: x, B: s}

	ptr := &st
	mp := map[string]int{"key": x}
	var anyVal any = st

	cp := complexStruct{
		S: st,
		P: ptr,
		A: arr,
		L: []string{s},
		M: mp,
	}
	fmt.Println("AfterComplex")

	if b {
		inner := x * 10
		fmt.Println(inner)
	}

	for i := 0; i < 1; i++ {
		loopVar := i + x
		fmt.Println(loopVar)
	}

	res := int(i8) + int(f32) + int(real(c64)) + arr[0] + sl[0] + st.A + ptr.A + mp["key"] + cp.S.A
	if anySt, ok := anyVal.(smallStruct); ok {
		res += anySt.A
	}

	return res
}

func main() {
	for i := 1; ; i++ {
		fmt.Printf("Result: %d\n", CoverageTarget(i, "test"))
		time.Sleep(500 * time.Millisecond)
	}
}
