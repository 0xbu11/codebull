//go:build !go1.23

package main

import (
	"fmt"
	"time"

	_ "github.com/0xbu11/codebull" // README-style: side-effect import starts the server/runtime
)

type demoInner struct {
	A int
	B string
	C []byte
}

type demoOuter struct {
	In    demoInner
	Ptr   *demoInner
	Arr   [4]int
	Slice []int
	Map   map[string]*demoInner
	Any   any
}

//go:noinline
func target(x int) int {
	b := (x%2 == 0)
	i8 := int8(x)
	i16 := int16(x * 2)
	i32 := int32(x * 3)
	i64 := int64(x) * 4
	u := uint(x)
	u64 := uint64(x) * 10
	f32 := float32(x) + 0.25
	f64 := float64(x) + 0.5
	c128 := complex(float64(x), float64(x+1))

	s := "hello"
	arr := [4]int{x, x + 1, x + 2, x + 3}
	sl := []int{x, x * 2, x * 3}
	inner := demoInner{A: x * 7, B: "bee", C: []byte{byte(x), 2, 3}}
	fmt.Println(b)

	return 1 + int(i8) + int(i16) + int(i32) + int(i64) + int(u) + int(u64) + int(f32) + int(f64) + int(real(c128)) + int(imag(c128)) +
		len(s) + arr[0] + arr[3] + sl[1] + inner.A + len(inner.B) + int(inner.C[0]) + int(inner.C[2])
}

func main() {
	fmt.Println("SDK loaded via blank import.")
	fmt.Println("Try: curl http://localhost:8888/health")

	for i := 1; i <= 100; i++ {
		fmt.Printf("target(%d) = %d\n", i, target(i))
		time.Sleep(1 * time.Second)
	}

	fmt.Println("Done")
}
