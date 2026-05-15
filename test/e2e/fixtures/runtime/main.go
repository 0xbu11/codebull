package main

import (
	"fmt"
	"runtime"
	"time"

	_ "github.com/0xbu11/codebull"
)

func main() {
	for i := 1; ; i++ {
		_ = make([]byte, 1024)
		
		_ = runtime.NumGoroutine()
		runtime.GC()
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		
		runtime.Gosched()
		
		ch := make(chan int, 1)
		ch <- 1
		<-ch
		
		fmt.Printf("Tick %d\n", i)
		
		time.Sleep(1 * time.Second)
	}
}
