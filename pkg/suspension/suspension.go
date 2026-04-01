//go:build !go1.23

package suspension

import (
	_ "unsafe"
)

//go:linkname startTheWorld runtime.startTheWorld
func startTheWorld()

//go:linkname stopTheWorld runtime.stopTheWorld
func stopTheWorld(reason uint8)

func StartTheWorld() {
	startTheWorld()
}

func StopTheWorld(reason string) {
	stopTheWorld(0)
}
