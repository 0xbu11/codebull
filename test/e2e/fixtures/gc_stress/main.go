package main

import (
	"fmt"
	"runtime"
	"time"

	_ "github.com/0xbu11/codebull"
)

func Work(id int, data string) {
	s := fmt.Sprintf("work-%d-%s", id, data)
	if len(s) > 100 {
		fmt.Println(s)
	}
}

func main() {
	go func() {
		for {
			_ = make([]byte, 1024*1024)
			runtime.GC()
			time.Sleep(1 * Millisecond)
		}
	}()

	fmt.Println("GC Stressor started, entering work loop...")
	for i := 0; ; i++ {
		Work(i, "some-payload-data")
		if i % 1000 == 0 {
			fmt.Printf("Iteration %d\n", i)
		}
		time.Sleep(100 * Microsecond)
	}
}

const (
	Millisecond = time.Millisecond
	Microsecond = time.Microsecond
)
