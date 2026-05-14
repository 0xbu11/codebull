package main

import (
	"fmt"
	"time"

	_ "github.com/0xbu11/codebull"
)

func DeepWork(depth int, salt int64) int64 {
	var buffer [1024]byte // 1KB per frame
	for i := range buffer {
		buffer[i] = byte(salt + int64(i))
	}
	
	if depth <= 0 {
		return salt
	}
	
	return DeepWork(depth-1, salt+int64(buffer[0]))
}

func main() {
	fmt.Println("Starting stack growth test...")
	for i := 0; ; i++ {
		res := DeepWork(50, int64(i))
		if i % 100 == 0 {
			fmt.Printf("Iteration %d, result %d\n", i, res)
		}
		time.Sleep(1 * time.Millisecond)
	}
}
