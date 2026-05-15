package main

import (
	"fmt"
	"time"

	_ "github.com/0xbu11/codebull"
)

type item struct {
	ID   int
	Name string
}

//go:noinline
func SliceTarget(n int) {
	ints := make([]int, n)
	for i := 0; i < n; i++ {
		ints[i] = i * 10
	}

	strings := []string{"hello", "world", "slice"}
	if n > len(strings) {
		strings = append(strings, "extra")
	}

	structs := []item{
		{ID: 1, Name: "first"},
		{ID: 2, Name: "second"},
	}

	nested := [][]int{
		{1, 2},
		{3, 4, 5},
	}

	large := make([]int, 200)
	for i := 0; i < 200; i++ {
		large[i] = i
	}

	fmt.Printf("SliceTarget: n=%d, len(ints)=%d, strings=%v, structs=%v, nested=%v, len(large)=%d\n", 
		n, len(ints), strings, structs, nested, len(large))
}

func main() {
	for i := 1; ; i++ {
		SliceTarget(i % 5 + 1)
		time.Sleep(1 * time.Second)
	}
}
