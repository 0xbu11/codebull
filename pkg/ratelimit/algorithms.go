package ratelimit

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"
)

type TokenBucketLimiter struct {
	rate       float64
	burst      float64
	tokens     float64
	lastUpdate time.Time
	mu         sync.Mutex
}

func NewTokenBucketLimiter(rate float64, burst int) *TokenBucketLimiter {
	return &TokenBucketLimiter{
		rate:       rate,
		burst:      float64(burst),
		tokens:     float64(burst),
		lastUpdate: time.Now(),
	}
}

func (l *TokenBucketLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.lastUpdate).Seconds()
	l.tokens += elapsed * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.lastUpdate = now

	if l.tokens >= 1.0 {
		l.tokens -= 1.0
		return true
	}
	return false
}

type FixedWindowLimiter struct {
	limit    int64
	window   time.Duration
	counter  int64
	deadline int64 // unix nano
}

func NewFixedWindowLimiter(limit int, window time.Duration) *FixedWindowLimiter {
	return &FixedWindowLimiter{
		limit:    int64(limit),
		window:   window,
		deadline: time.Now().Add(window).UnixNano(),
	}
}

func (l *FixedWindowLimiter) Allow() bool {
	now := time.Now().UnixNano()
	deadline := atomic.LoadInt64(&l.deadline)

	if now > deadline {
		newDeadline := now + l.window.Nanoseconds()
		if atomic.CompareAndSwapInt64(&l.deadline, deadline, newDeadline) {
			atomic.StoreInt64(&l.counter, 1)
			return true
		}
	}

	count := atomic.AddInt64(&l.counter, 1)
	return count <= l.limit
}

type ProbabilisticLimiter struct {
	probability float64
	rng         *rand.Rand
	mu          sync.Mutex
}

func NewProbabilisticLimiter(probability float64) *ProbabilisticLimiter {
	return &ProbabilisticLimiter{
		probability: probability,
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (l *ProbabilisticLimiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rng.Float64() < l.probability
}

type CounterLimiter struct {
	n       uint64
	counter uint64
}

func NewCounterLimiter(n int) *CounterLimiter {
	return &CounterLimiter{
		n: uint64(n),
	}
}

func (l *CounterLimiter) Allow() bool {
	if l.n <= 1 {
		return true
	}
	count := atomic.AddUint64(&l.counter, 1)
	return (count % l.n) == 0
}
