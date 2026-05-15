package main

import (
	"fmt"
	"time"

	_ "github.com/0xbu11/codebull"
)

type State struct {
	Count int
	Name  string
}

//go:noinline
func PointerTarget(s *State, val int) {
	s.Count = val
	ptr := &val
	
	fmt.Printf("PointerTarget: s=%p, val=%d, ptr=%p\n", s, val, ptr)
}

func main() {
	st := &State{Count: 0, Name: "Initial"}
	for i := 1; ; i++ {
		PointerTarget(st, i)
		time.Sleep(1 * time.Second)
	}
}
