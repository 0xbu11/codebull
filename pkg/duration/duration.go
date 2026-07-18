//go:build !go1.27

package duration

import (
	"fmt"
	"sync"
	"sync/atomic"
)

type Role uint8

const (
	RoleEntry Role = iota + 1
	RoleExit
)

const maxPairID = 1<<16 - 1

type PointMeta struct {
	Role         Role
	PairID       uint64
	FunctionName string
	EntryLine    int
	EndLine      int
	EntryPC      uint64
	ExitPC       uint64
}

var (
	regMu      sync.Mutex
	nextPairID uint64
	lookupV    atomic.Value // map[uint64]PointMeta, immutable snapshots
	activeN    atomic.Int32

	goidFn     func() int64
	nanoFn     func() int64
	hooksReady atomic.Bool
)

var (
	cCompleted      atomic.Int64
	cDroppedEntries atomic.Int64
	cUnmatchedExits atomic.Int64
	cEvicted        atomic.Int64
	cDroppedSamples atomic.Int64
	cReentered      atomic.Int64
	cNoGoid         atomic.Int64
)

type Stats struct {
	ActivePairs    int   `json:"active_pairs"`
	Completed      int64 `json:"completed"`
	DroppedEntries int64 `json:"dropped_entries"`
	UnmatchedExits int64 `json:"unmatched_exits"`
	EvictedEntries int64 `json:"evicted_entries"`
	DroppedSamples int64 `json:"dropped_samples"`
	ReenteredPairs int64 `json:"reentered_pairs"`
	NoGoidHits     int64 `json:"no_goid_hits"`
}

func SetRuntimeHooks(goid, nano func() int64) {
	regMu.Lock()
	defer regMu.Unlock()
	goidFn = goid
	nanoFn = nano
	hooksReady.Store(goid != nil && nano != nil)
}

func RuntimeHooksReady() bool { return hooksReady.Load() }

func lookupMap() map[uint64]PointMeta {
	m, _ := lookupV.Load().(map[uint64]PointMeta)
	return m
}

func Register(functionName string, entryPC, exitPC uint64, entryLine, endLine int) (uint64, error) {
	if !hooksReady.Load() {
		return 0, fmt.Errorf("duration instrumentation unavailable: goroutine id discovery failed or pkg/trap not linked")
	}
	if entryPC == 0 || exitPC == 0 || entryPC == exitPC {
		return 0, fmt.Errorf("invalid duration pair: entry=0x%x exit=0x%x", entryPC, exitPC)
	}

	regMu.Lock()
	defer regMu.Unlock()

	cur := lookupMap()
	if meta, ok := cur[entryPC]; ok {
		return 0, fmt.Errorf("PC 0x%x already registered for duration pair %d", entryPC, meta.PairID)
	}
	if meta, ok := cur[exitPC]; ok {
		return 0, fmt.Errorf("PC 0x%x already registered for duration pair %d", exitPC, meta.PairID)
	}
	if nextPairID >= maxPairID {
		return 0, fmt.Errorf("duration pair limit (%d) exhausted", maxPairID)
	}
	nextPairID++
	id := nextPairID

	meta := PointMeta{
		PairID:       id,
		FunctionName: functionName,
		EntryLine:    entryLine,
		EndLine:      endLine,
		EntryPC:      entryPC,
		ExitPC:       exitPC,
	}
	next := make(map[uint64]PointMeta, len(cur)+2)
	for k, v := range cur {
		next[k] = v
	}
	entry := meta
	entry.Role = RoleEntry
	exit := meta
	exit.Role = RoleExit
	next[entryPC] = entry
	next[exitPC] = exit

	lookupV.Store(next)
	activeN.Add(1)
	startBackgroundOnce()
	return id, nil
}

func Unregister(pairID uint64) error {
	regMu.Lock()
	cur := lookupMap()
	next := make(map[uint64]PointMeta, len(cur))
	found := false
	for k, v := range cur {
		if v.PairID == pairID {
			found = true
			continue
		}
		next[k] = v
	}
	if found {
		lookupV.Store(next)
		activeN.Add(-1)
	}
	regMu.Unlock()

	if !found {
		return fmt.Errorf("duration pair %d not registered", pairID)
	}
	purgePair(pairID)
	return nil
}

func LookupPC(pc uint64) (PointMeta, bool) {
	meta, ok := lookupMap()[pc]
	return meta, ok
}

func ActivePairs() int { return int(activeN.Load()) }

func HandleHit(pc uint64) bool {
	if activeN.Load() == 0 {
		return false
	}
	meta, ok := lookupMap()[pc]
	if !ok {
		return false
	}
	gid := goidFn()
	if gid <= 0 {
		cNoGoid.Add(1)
		return true
	}
	now := nanoFn()
	key := pairKey(gid, meta.PairID)
	if meta.Role == RoleEntry {
		recordEntry(key, now)
	} else {
		recordExit(&meta, key, gid, now)
	}
	return true
}

func pairKey(gid int64, pairID uint64) uint64 {
	return uint64(gid)<<16 | (pairID & maxPairID)
}

func GetStats() Stats {
	return Stats{
		ActivePairs:    ActivePairs(),
		Completed:      cCompleted.Load(),
		DroppedEntries: cDroppedEntries.Load(),
		UnmatchedExits: cUnmatchedExits.Load(),
		EvictedEntries: cEvicted.Load(),
		DroppedSamples: cDroppedSamples.Load(),
		ReenteredPairs: cReentered.Load(),
		NoGoidHits:     cNoGoid.Load(),
	}
}
