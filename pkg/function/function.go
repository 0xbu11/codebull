//go:build !go1.23

package function

import (
	"debug/dwarf"

	"github.com/0xbu11/codebull/pkg/variable"
)

type Function struct {
	Name           string
	Entry          uint64
	End            uint64
	Offset         dwarf.Offset
	Prologue       []byte
	MorestackAddr  uint64
	Variables      []*variable.Variable
	RegsUsed       []uint64
	StackFrameSize int32
}
