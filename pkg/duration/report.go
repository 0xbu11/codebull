//go:build !go1.27

package duration

import (
	"github.com/0xbu11/codebull/pkg/ratelimit"
)

type Sample struct {
	FunctionName string
	EntryLine    int
	EndLine      int
	PairID       uint64
	Goid         int64
	DurationNs   int64
	ExitPC       uint64
}

var onSample func(Sample)

func SetOnSample(fn func(Sample)) { onSample = fn }

var sampleCh = make(chan Sample, 4096)

func emitSample(meta *PointMeta, gid, durationNs int64) {
	s := Sample{
		FunctionName: meta.FunctionName,
		EntryLine:    meta.EntryLine,
		EndLine:      meta.EndLine,
		PairID:       meta.PairID,
		Goid:         gid,
		DurationNs:   durationNs,
		ExitPC:       meta.ExitPC,
	}
	// Count the hit at the exit trap rather than after the queue, so a pair that
	// is dropped for either reason below still shows up in the hit count.
	ratelimit.Global().CountHit(meta.ExitPC)
	select {
	case sampleCh <- s:
	default:
		cDroppedSamples.Add(1)
		ratelimit.Global().CountDrop(meta.ExitPC)
	}
}

func sampleLoop() {
	for s := range sampleCh {
		if !ratelimit.Global().Decide(s.ExitPC) {
			continue
		}
		if fn := onSample; fn != nil {
			fn(s)
		}
	}
}
