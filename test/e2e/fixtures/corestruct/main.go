package main

import (
	"fmt"
	"time"

	_ "github.com/0xbu11/codebull"
)

//go:noinline
func useMap(m map[int]string) {
	m[1] = "hello_map"
}

//go:noinline
func useChan(c chan int) {
	select {
	case c <- 42:
	default:
	}
}

//go:noinline
func useInterface(i interface{}) {
	_ = fmt.Sprintf("interface value: %v", i)
}

func main() {
	for {
		m := make(map[int]string)
		useMap(m)

		c := make(chan int, 1)
		useChan(c)

		useInterface("test_interface_string")

		go func() {
			_ = 1 + 1
		}()

		time.Sleep(1 * time.Second)
	}
}
