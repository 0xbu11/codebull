package main

import (
	"fmt"
	"runtime"
	"time"

	_ "github.com/0xbu11/codebull"
)

func TightLoop(n int) int {
	sum := 0
	for i := 0; i < n; i++ {
		sum += i
		if i % 1000000 == 0 {
			sum ^= i
		}
	}
	return sum
}

func main() {
	
	fmt.Println("Starting preemption test...")
	
	go func() {
		for {
			time.Sleep(1 * time.Microsecond)
			runtime.Gosched()
		}
	}()

	for i := 0; ; i++ {
		res := TightLoop(100000000)
		fmt.Printf("Iteration %d, result %d\n", i, res)
	}
}
