//go:build !go1.27

package duration

import (
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

const (
	shardCount  = 64
	shardSlots  = 1024
	probeWindow = 16

	defaultTTL = 60 * time.Second
	sweepEvery = time.Second
)

type slot struct {
	key atomic.Uint64 // pairKey(goid, pairID); 0 = empty
	t0  atomic.Int64  // monotonic ns at entry; 0 = mid-publish
}

type shard struct {
	slots [shardSlots]slot
}

var table [shardCount]shard

func slotIndex(key uint64) (shardIdx, base uint64) {
	h := key * 0x9E3779B97F4A7C15
	return h >> 58, (h >> 32) & (shardSlots - 1)
}

func recordEntry(key uint64, now int64) {
	shardIdx, base := slotIndex(key)
	sh := &table[shardIdx]

	for i := uint64(0); i < probeWindow; i++ {
		s := &sh.slots[(base+i)&(shardSlots-1)]
		if s.key.Load() == key {
			s.t0.Store(now)
			cReentered.Add(1)
			return
		}
	}
	for i := uint64(0); i < probeWindow; i++ {
		s := &sh.slots[(base+i)&(shardSlots-1)]
		if s.key.Load() == 0 && s.key.CompareAndSwap(0, key) {
			s.t0.Store(now)
			return
		}
	}
	cDroppedEntries.Add(1)
}

func recordExit(meta *PointMeta, key uint64, gid, now int64) {
	shardIdx, base := slotIndex(key)
	sh := &table[shardIdx]
	for i := uint64(0); i < probeWindow; i++ {
		s := &sh.slots[(base+i)&(shardSlots-1)]
		if s.key.Load() != key {
			continue
		}
		t0 := s.t0.Load()
		s.t0.Store(0)
		s.key.Store(0)
		if t0 == 0 {
			cUnmatchedExits.Add(1)
			return
		}
		cCompleted.Add(1)
		emitSample(meta, gid, now-t0)
		return
	}
	cUnmatchedExits.Add(1)
}

func purgePair(pairID uint64) {
	id := pairID & maxPairID
	for si := range table {
		for i := range table[si].slots {
			s := &table[si].slots[i]
			k := s.key.Load()
			if k != 0 && k&maxPairID == id {
				s.t0.Store(0)
				s.key.CompareAndSwap(k, 0)
			}
		}
	}
}

func PendingCount(pairID uint64) int {
	id := pairID & maxPairID
	n := 0
	for si := range table {
		for i := range table[si].slots {
			s := &table[si].slots[i]
			k := s.key.Load()
			if k != 0 && k&maxPairID == id && s.t0.Load() != 0 {
				n++
			}
		}
	}
	return n
}

var (
	backgroundOnce sync.Once
	ttlNs          atomic.Int64
)

func entryTTL() int64 {
	if v := ttlNs.Load(); v > 0 {
		return v
	}
	ttl := defaultTTL
	if raw := os.Getenv("EGO_SHADOW_DURATION_TTL"); raw != "" {
		if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
			ttl = time.Duration(secs) * time.Second
		}
	}
	ttlNs.Store(int64(ttl))
	return int64(ttl)
}

func setTTLForTest(d time.Duration) { ttlNs.Store(int64(d)) }

func startBackgroundOnce() {
	backgroundOnce.Do(func() {
		go sweeperLoop()
		go sampleLoop()
	})
}

func sweeperLoop() {
	ticker := time.NewTicker(sweepEvery)
	defer ticker.Stop()
	for range ticker.C {
		sweepExpired()
	}
}

func sweepExpired() {
	if !hooksReady.Load() {
		return
	}
	now := nanoFn()
	ttl := entryTTL()
	for si := range table {
		for i := range table[si].slots {
			s := &table[si].slots[i]
			k := s.key.Load()
			if k == 0 {
				continue
			}
			t0 := s.t0.Load()
			if t0 == 0 || now-t0 <= ttl {
				continue
			}
			s.t0.Store(0)
			if s.key.CompareAndSwap(k, 0) {
				cEvicted.Add(1)
			}
		}
	}
}
