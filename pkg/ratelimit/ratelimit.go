package ratelimit

import "time"

type Limiter interface {
	Allow() bool
}

type Config struct {
	Algorithm string        `json:"algorithm"`
	Rate      float64       `json:"rate"`
	Burst     int           `json:"burst,omitempty"`
	Window    time.Duration `json:"window,omitempty"`
}
