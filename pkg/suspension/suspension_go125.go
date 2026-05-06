//go:build go1.25 && !go1.27

package suspension

func StartTheWorld() {}

func StopTheWorld(reason string) {
	_ = reason
}
