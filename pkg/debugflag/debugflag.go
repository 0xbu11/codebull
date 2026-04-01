package debugflag

import (
	"log"
	"os"
	"strings"
	"sync/atomic"
)

var enabled atomic.Bool

func init() {
	enabled.Store(parseBool(os.Getenv("EGO_SHADOW_DEBUG")))
}

func parseBool(raw string) bool {
	v := strings.ToLower(strings.TrimSpace(raw))
	switch v {
	case "1", "true", "yes", "y", "on", "debug":
		return true
	default:
		return false
	}
}

func SetEnabled(v bool) {
	enabled.Store(v)
}

func Enabled() bool {
	return enabled.Load()
}

func Printf(format string, args ...any) {
	if !enabled.Load() {
		return
	}
	log.Printf(format, args...)
}

func Println(args ...any) {
	if !enabled.Load() {
		return
	}
	log.Println(args...)
}
