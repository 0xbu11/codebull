package ratelimit

import (
	"sync"
	"time"
)

type Registry struct {
	mu             sync.RWMutex
	limiters       map[uint64]Limiter
	configs        map[uint64]Config // Store configs for reporting
	defaultLimiter Limiter
	defaultConfig  *Config
}

var globalRegistry = &Registry{
	limiters: make(map[uint64]Limiter),
	configs:  make(map[uint64]Config),
	defaultConfig: &Config{
		Algorithm: "token_bucket",
		Rate:      1000.0,
		Burst:     1000,
	},
	defaultLimiter: NewTokenBucketLimiter(1.0, 1),
}

func Global() *Registry {
	return globalRegistry
}

func (r *Registry) SetDefaultLimiter(cfg *Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultConfig = cfg
	if cfg != nil {
		r.defaultLimiter = CreateLimiter(*cfg)
	} else {
		r.defaultLimiter = nil
	}
}

func (r *Registry) GetDefaultConfig() *Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultConfig
}

func (r *Registry) Register(pc uint64, cfg Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.configs[pc] = cfg
	r.limiters[pc] = CreateLimiter(cfg)
}

func (r *Registry) Unregister(pc uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.configs, pc)
	delete(r.limiters, pc)
}

func (r *Registry) Get(pc uint64) Limiter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if l, ok := r.limiters[pc]; ok {
		return l
	}
	return r.defaultLimiter
}

func (r *Registry) GetConfig(pc uint64) *Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if cfg, ok := r.configs[pc]; ok {
		return &cfg
	}
	return r.defaultConfig
}

func (r *Registry) GetAllConfigs() map[uint64]Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make(map[uint64]Config, len(r.configs))
	for k, v := range r.configs {
		res[k] = v
	}
	return res
}

func (r *Registry) Allow(pc uint64) bool {
	l := r.Get(pc)
	if l == nil {
		return true // Default to allow if no limiter is configured
	}
	return l.Allow()
}

func CreateLimiter(cfg Config) Limiter {
	switch cfg.Algorithm {
	case "token_bucket":
		burst := cfg.Burst
		if burst <= 0 {
			burst = int(cfg.Rate)
			if burst <= 0 {
				burst = 1
			}
		}
		return NewTokenBucketLimiter(cfg.Rate, burst)
	case "fixed_window":
		window := cfg.Window
		if window == 0 {
			window = time.Second
		}
		return NewFixedWindowLimiter(int(cfg.Rate), window)
	case "probabilistic":
		return NewProbabilisticLimiter(cfg.Rate)
	case "counter":
		return NewCounterLimiter(int(cfg.Rate))
	default:
		return nil
	}
}
