package main

import (
	"time"

	_ "github.com/0xbu11/codebull"
)

//go:noinline
func work(n int) int {
	sum := 0 // duration-entry
	for i := 0; i < n; i++ {
		sum += i
	}
	time.Sleep(5 * time.Millisecond)
	return sum // duration-exit
}

func main() {
	for {
		_ = work(1000)
		time.Sleep(20 * time.Millisecond)
	}
}
