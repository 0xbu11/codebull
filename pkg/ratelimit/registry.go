package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"
)

// Stats is what a single instrumented address did since process start.
//
// Hits is counted before the limiter runs, so it stays exact no matter how
// aggressively events are sampled. Allowed is what reached the collector;
// Dropped is what was thrown away. Hits == Allowed + Dropped.
//
// The counters are cumulative on purpose: a consumer that wants a window reads
// twice and subtracts. Reporting a window directly would invite the mistake of
// comparing a cumulative hit count against a windowed counter difference.
type Stats struct {
	Hits    int64 `json:"hits"`
	Allowed int64 `json:"allowed"`
	Dropped int64 `json:"dropped"`
}

// SamplingRatio is Allowed/Hits, or 1 when nothing has been observed yet.
func (s Stats) SamplingRatio() float64 {
	if s.Hits <= 0 {
		return 1
	}
	return float64(s.Allowed) / float64(s.Hits)
}

// Complete reports whether every hit made it through.
func (s Stats) Complete() bool { return s.Dropped == 0 }

type entry struct {
	limiter  Limiter
	cfg      Config
	explicit bool // configured per point rather than inherited from the default

	hits    atomic.Int64
	allowed atomic.Int64
	dropped atomic.Int64
}

func (e *entry) stats() Stats {
	return Stats{
		Hits:    e.hits.Load(),
		Allowed: e.allowed.Load(),
		Dropped: e.dropped.Load(),
	}
}

// Registry decides, per instrumented address, whether an event is collected.
//
// Every address gets its own limiter. Adding a tracepoint therefore does not
// lower the budget of the tracepoints already attached — the earlier design
// shared one bucket across every point, which made the effective per-point
// limit depend on how many other points happened to be attached.
//
// A single ceiling limiter still guards the process as a whole, but it sits far
// above any sane per-point rate and every rejection it makes is counted.
type Registry struct {
	mu      sync.RWMutex
	entries map[uint64]*entry

	defaultConfig *Config

	ceilingLimiter Limiter
	ceilingConfig  *Config
	ceilingDropped atomic.Int64

	since time.Time
}

// DefaultPointRate is the per-point budget applied to any address registered
// without an explicit config.
const DefaultPointRate = 1000.0

// DefaultCeilingRate is the process-wide safety net shared by every point. It
// exists to stop instrumentation from taking the observed process down, not to
// shape data, so it sits well above the sum of realistic per-point rates.
const DefaultCeilingRate = 50000.0

var globalRegistry = &Registry{
	entries: make(map[uint64]*entry),
	defaultConfig: &Config{
		Algorithm: "token_bucket",
		Rate:      DefaultPointRate,
		Burst:     int(DefaultPointRate),
	},
	ceilingConfig: &Config{
		Algorithm: "token_bucket",
		Rate:      DefaultCeilingRate,
		Burst:     int(DefaultCeilingRate),
	},
	ceilingLimiter: NewTokenBucketLimiter(DefaultCeilingRate, int(DefaultCeilingRate)),
	since:          time.Now(),
}

func Global() *Registry {
	return globalRegistry
}

// SetDefaultLimiter changes the budget handed to points that have no explicit
// config. Points already attached pick the new budget up immediately; their
// counters are preserved so a mid-window change does not erase the evidence of
// what happened before it.
func (r *Registry) SetDefaultLimiter(cfg *Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultConfig = cfg
	for _, e := range r.entries {
		if e.explicit {
			continue
		}
		if cfg == nil {
			e.limiter = nil
			e.cfg = Config{}
			continue
		}
		e.limiter = CreateLimiter(*cfg)
		e.cfg = *cfg
	}
}

func (r *Registry) GetDefaultConfig() *Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultConfig
}

// SetCeilingLimiter replaces the process-wide safety net. Passing nil removes
// it, leaving only per-point budgets.
func (r *Registry) SetCeilingLimiter(cfg *Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ceilingConfig = cfg
	if cfg == nil {
		r.ceilingLimiter = nil
		return
	}
	r.ceilingLimiter = CreateLimiter(*cfg)
}

func (r *Registry) GetCeilingConfig() *Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.ceilingConfig
}

func (r *Registry) Register(pc uint64, cfg Config) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[pc]
	if !ok {
		e = &entry{}
		r.entries[pc] = e
	}
	e.cfg = cfg
	e.explicit = true
	e.limiter = CreateLimiter(cfg)
}

func (r *Registry) Unregister(pc uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, pc)
}

func (r *Registry) entryFor(pc uint64) *entry {
	r.mu.RLock()
	e, ok := r.entries[pc]
	r.mu.RUnlock()
	if ok {
		return e
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if e, ok := r.entries[pc]; ok {
		return e
	}
	e = &entry{}
	if r.defaultConfig != nil {
		e.cfg = *r.defaultConfig
		e.limiter = CreateLimiter(*r.defaultConfig)
	}
	r.entries[pc] = e
	return e
}

func (r *Registry) Get(pc uint64) Limiter {
	return r.entryFor(pc).limiter
}

func (r *Registry) GetConfig(pc uint64) *Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if e, ok := r.entries[pc]; ok && e.explicit {
		cfg := e.cfg
		return &cfg
	}
	return r.defaultConfig
}

func (r *Registry) GetAllConfigs() map[uint64]Config {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make(map[uint64]Config, len(r.entries))
	for pc, e := range r.entries {
		res[pc] = e.cfg
	}
	return res
}

// CountHit records that the instrumented address was reached. Callers that
// decide separately whether to keep the event (the duration path queues first
// and samples later) use this so the hit count stays exact.
func (r *Registry) CountHit(pc uint64) {
	r.entryFor(pc).hits.Add(1)
}

// CountDrop records an event lost for a reason other than the limiter, such as
// a full queue. It keeps Hits == Allowed + Dropped true.
func (r *Registry) CountDrop(pc uint64) {
	r.entryFor(pc).dropped.Add(1)
}

// Decide applies the point budget and then the process ceiling, recording the
// outcome. It does not count a hit.
func (r *Registry) Decide(pc uint64) bool {
	e := r.entryFor(pc)

	if e.limiter != nil && !e.limiter.Allow() {
		e.dropped.Add(1)
		return false
	}

	r.mu.RLock()
	ceiling := r.ceilingLimiter
	r.mu.RUnlock()
	if ceiling != nil && !ceiling.Allow() {
		e.dropped.Add(1)
		r.ceilingDropped.Add(1)
		return false
	}

	e.allowed.Add(1)
	return true
}

// Observe counts a hit and returns whether the event should be collected.
func (r *Registry) Observe(pc uint64) bool {
	r.CountHit(pc)
	return r.Decide(pc)
}

// Allow is retained for callers that predate the counters; it behaves exactly
// like Observe.
func (r *Registry) Allow(pc uint64) bool {
	return r.Observe(pc)
}

// StatsFor returns the cumulative counters for one address.
func (r *Registry) StatsFor(pc uint64) Stats {
	r.mu.RLock()
	e, ok := r.entries[pc]
	r.mu.RUnlock()
	if !ok {
		return Stats{}
	}
	return e.stats()
}

// PointSnapshot is one address's configuration and counters.
type PointSnapshot struct {
	PC       uint64 `json:"pc"`
	Config   Config `json:"config"`
	Explicit bool   `json:"explicit"`
	Stats
}

// Snapshot is a consistent read of the whole registry.
type Snapshot struct {
	Since          time.Time       `json:"since"`
	Default        *Config         `json:"default"`
	Ceiling        *Config         `json:"ceiling,omitempty"`
	CeilingDropped int64           `json:"ceiling_dropped"`
	Totals         Stats           `json:"totals"`
	Points         []PointSnapshot `json:"points"`
}

func (r *Registry) Snapshot() Snapshot {
	r.mu.RLock()
	defer r.mu.RUnlock()

	snap := Snapshot{
		Since:          r.since,
		Default:        r.defaultConfig,
		Ceiling:        r.ceilingConfig,
		CeilingDropped: r.ceilingDropped.Load(),
		Points:         make([]PointSnapshot, 0, len(r.entries)),
	}
	for pc, e := range r.entries {
		s := e.stats()
		snap.Totals.Hits += s.Hits
		snap.Totals.Allowed += s.Allowed
		snap.Totals.Dropped += s.Dropped
		snap.Points = append(snap.Points, PointSnapshot{
			PC:       pc,
			Config:   e.cfg,
			Explicit: e.explicit,
			Stats:    s,
		})
	}
	return snap
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
