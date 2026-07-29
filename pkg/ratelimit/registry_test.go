package ratelimit

import "testing"

// A limited point must still report every hit: the count is what gets
// reconciled against the observed service's own counters, so sampling may thin
// the payloads but must never change the number.
func TestObserveCountsEveryHitWhileDropping(t *testing.T) {
	r := newTestRegistry(Config{Algorithm: "token_bucket", Rate: 0, Burst: 10})

	const pc = 0x1000
	allowed := 0
	for i := 0; i < 100; i++ {
		if r.Observe(pc) {
			allowed++
		}
	}

	stats := r.StatsFor(pc)
	if stats.Hits != 100 {
		t.Fatalf("hits = %d, want 100", stats.Hits)
	}
	if stats.Allowed != int64(allowed) {
		t.Fatalf("allowed = %d, want %d", stats.Allowed, allowed)
	}
	if stats.Hits != stats.Allowed+stats.Dropped {
		t.Fatalf("hits %d != allowed %d + dropped %d", stats.Hits, stats.Allowed, stats.Dropped)
	}
	if stats.Dropped == 0 {
		t.Fatal("expected the burst-10 bucket to drop something")
	}
	if stats.Complete() {
		t.Fatal("Complete() must be false once anything was dropped")
	}
	if got := stats.SamplingRatio(); got != float64(allowed)/100 {
		t.Fatalf("sampling ratio = %v, want %v", got, float64(allowed)/100)
	}
}

// Attaching a second point must not eat the first point's budget. This is the
// regression that made 20 attached tracepoints under-report by different
// amounts each.
func TestPointsDoNotShareABudget(t *testing.T) {
	r := newTestRegistry(Config{Algorithm: "token_bucket", Rate: 0, Burst: 10})

	const (
		hot  = 0x2000
		cold = 0x3000
	)
	for i := 0; i < 50; i++ {
		r.Observe(hot)
	}

	coldAllowed := 0
	for i := 0; i < 10; i++ {
		if r.Observe(cold) {
			coldAllowed++
		}
	}

	if coldAllowed != 10 {
		t.Fatalf("cold point collected %d/10 events; a busy neighbour drained its bucket", coldAllowed)
	}
	if dropped := r.StatsFor(hot).Dropped; dropped != 40 {
		t.Fatalf("hot point dropped %d, want 40", dropped)
	}
}

// The ceiling is shared by design, but every rejection it makes is counted
// against both the point and the ceiling so it can never fail silently.
func TestCeilingDropsAreCounted(t *testing.T) {
	r := newTestRegistry(Config{Algorithm: "token_bucket", Rate: 1000, Burst: 1000})
	r.SetCeilingLimiter(&Config{Algorithm: "token_bucket", Rate: 0, Burst: 5})

	const pc = 0x4000
	for i := 0; i < 20; i++ {
		r.Observe(pc)
	}

	stats := r.StatsFor(pc)
	if stats.Allowed != 5 {
		t.Fatalf("allowed = %d, want 5", stats.Allowed)
	}
	if stats.Hits != 20 {
		t.Fatalf("hits = %d, want 20", stats.Hits)
	}
	if snap := r.Snapshot(); snap.CeilingDropped != 15 {
		t.Fatalf("ceiling dropped = %d, want 15", snap.CeilingDropped)
	}
}

// Raising the default mid-window must reach points that are already attached,
// otherwise the fix only applies to tracepoints added afterwards.
func TestDefaultChangeAppliesToAttachedPoints(t *testing.T) {
	r := newTestRegistry(Config{Algorithm: "token_bucket", Rate: 0, Burst: 1})

	const pc = 0x5000
	r.Observe(pc)
	if r.Observe(pc) {
		t.Fatal("second event should have been dropped by the burst-1 bucket")
	}

	r.SetDefaultLimiter(&Config{Algorithm: "token_bucket", Rate: 10000, Burst: 10000})
	if !r.Observe(pc) {
		t.Fatal("raising the default did not reach the already attached point")
	}

	if stats := r.StatsFor(pc); stats.Hits != 3 {
		t.Fatalf("hits = %d, want 3 (counters must survive a config change)", stats.Hits)
	}
}

// An explicit per-point config outranks the default and is reported as such.
func TestExplicitConfigWinsOverDefault(t *testing.T) {
	r := newTestRegistry(Config{Algorithm: "token_bucket", Rate: 0, Burst: 1})

	const pc = 0x6000
	r.Register(pc, Config{Algorithm: "token_bucket", Rate: 1000, Burst: 1000})
	for i := 0; i < 5; i++ {
		if !r.Observe(pc) {
			t.Fatalf("event %d dropped despite an explicit 1000/s budget", i)
		}
	}

	snap := r.Snapshot()
	if len(snap.Points) != 1 || !snap.Points[0].Explicit {
		t.Fatalf("snapshot did not mark the point as explicitly configured: %+v", snap.Points)
	}
	if snap.Totals.Hits != 5 {
		t.Fatalf("totals.hits = %d, want 5", snap.Totals.Hits)
	}
}

// The duration path counts the hit at the exit trap and reports a queue
// overflow through the same counters as a limiter drop.
func TestCountHitAndCountDropStayConsistent(t *testing.T) {
	r := newTestRegistry(Config{Algorithm: "token_bucket", Rate: 1000, Burst: 1000})

	const pc = 0x7000
	r.CountHit(pc)
	r.CountDrop(pc)
	r.CountHit(pc)
	if !r.Decide(pc) {
		t.Fatal("Decide should allow under a 1000/s budget")
	}

	stats := r.StatsFor(pc)
	if stats.Hits != 2 || stats.Dropped != 1 || stats.Allowed != 1 {
		t.Fatalf("stats = %+v, want hits 2 / dropped 1 / allowed 1", stats)
	}
}

func newTestRegistry(def Config) *Registry {
	return &Registry{
		entries:       make(map[uint64]*entry),
		defaultConfig: &def,
	}
}
