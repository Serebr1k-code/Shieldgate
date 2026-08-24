package state

import (
	"math"
	"math/rand"
	"sort"
	"time"

	"shieldgate/internal/engine/classifier"
)

// CheckerFunc reports the current checker status for a service.
type CheckerFunc func(serviceID string) CheckerStatus

// SleepFunc pauses for d (injectable in tests).
type SleepFunc func(d time.Duration)

// OptimizerState holds the mutable state of one optimization loop.
type OptimizerState struct {
	AllowedGroups    map[string]*classifier.FlowGroup
	BannedGroups     map[string]*classifier.FlowGroup
	TempBanned       map[string]*classifier.FlowGroup
	CycleStart       time.Time
	CheckStartStatus CheckerStatus
	CycleCount       int

	nowFn func() time.Time
}

func NewOptimizerState(now time.Time, nowFn func() time.Time) *OptimizerState {
	return &OptimizerState{
		AllowedGroups: make(map[string]*classifier.FlowGroup),
		BannedGroups:  make(map[string]*classifier.FlowGroup),
		TempBanned:    make(map[string]*classifier.FlowGroup),
		CycleStart:    now,
		nowFn:         nowFn,
	}
}

// SyncAllowed refreshes the Allowed set from the matcher (new groups may
// have appeared since the state was created).
func (st *OptimizerState) SyncAllowed(groups []*classifier.FlowGroup) {
	for _, g := range groups {
		switch g.GetStatus() {
		case classifier.GroupAllowed:
			if _, ok := st.BannedGroups[g.ID]; !ok && !st.isTemp(g.ID) {
				st.AllowedGroups[g.ID] = g
			}
		case classifier.GroupBanned:
			delete(st.AllowedGroups, g.ID)
			st.BannedGroups[g.ID] = g
		case classifier.GroupTempBanned:
			delete(st.AllowedGroups, g.ID)
			st.TempBanned[g.ID] = g
		}
	}
}

func (st *OptimizerState) isTemp(id string) bool { _, ok := st.TempBanned[id]; return ok }

// weightedSample picks k items without replacement with probability
// proportional to Weight (Efraimidis–Spirakis).
func weightedSample(items []*classifier.FlowGroup, k int, rng *rand.Rand) []*classifier.FlowGroup {
	type keyed struct {
		g *classifier.FlowGroup
		v float64
	}
	keys := make([]keyed, 0, len(items))
	for _, it := range items {
		w := math.Max(it.Weight, 0.1)
		u := 1 - rng.Float64() // in (0,1]
		keys = append(keys, keyed{it, math.Log(u) / w})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].v > keys[j].v })
	out := make([]*classifier.FlowGroup, 0, k)
	for i := 0; i < k && i < len(keys); i++ {
		out = append(out, keys[i].g)
	}
	return out
}

// SelectForTempBan chooses ~fraction of allowed groups via weighted random.
// Groups marked IsChecker=true are excluded.
func (o *OptimizeRunner) selectFraction(rng *rand.Rand) []*classifier.FlowGroup {
	st := o.state
	var candidates []*classifier.FlowGroup
	totalWeight := 0.0
	for _, g := range st.AllowedGroups {
		if g.IsChecker != nil && *g.IsChecker {
			continue // user-marked checker traffic is never banned
		}
		candidates = append(candidates, g)
		totalWeight += g.Weight
	}
	n := int(math.Floor(float64(len(candidates)) * o.banFraction))
	if n < 1 {
		n = minInt(1, len(candidates))
	}
	if n > len(candidates) {
		n = len(candidates)
	}
	return weightedSample(candidates, n, rng)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CycleResult summarizes what happened during one optimization cycle.
type CycleResult struct {
	BannedIDs []string // temp-ban promoted to permanent ban
	Restored  []string // returned to allowed after failure
	Success   bool
}

// OptimizeRunner drives optimization cycles for a single service.
type OptimizeRunner struct {
	state       *OptimizerState
	serviceID   string
	banFraction float64
	wait        time.Duration // n*2 window
	checker     CheckerFunc
	sleep       SleepFunc
	rng         *rand.Rand
	nowFn       func() time.Time
}

func NewOptimizeRunner(state *OptimizerState, serviceID string, banFraction float64, wait time.Duration, checker CheckerFunc, sleep SleepFunc) *OptimizeRunner {
	return &OptimizeRunner{
		state:       state,
		serviceID:   serviceID,
		banFraction: banFraction,
		wait:        wait,
		checker:     checker,
		sleep:       sleep,
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
		nowFn:       time.Now,
	}
}

func (o *OptimizeRunner) SetClock(f func() time.Time) { o.nowFn = f }

// WaitForGreen blocks until the checker is green or ctx-ish attempts run out.
func (o *OptimizeRunner) WaitForGreen(maxAttempts int) bool {
	for i := 0; i < maxAttempts; i++ {
		if o.checker(o.serviceID) == CheckerGreen {
			return true
		}
		o.sleep(o.wait)
	}
	return o.checker(o.serviceID) == CheckerGreen
}

// RunCycle executes one full 1/4-ban cycle:
// select fraction → temp-ban → wait n*2 → check → promote/rollback.
func (o *OptimizeRunner) RunCycle() CycleResult {
	st := o.state
	res := CycleResult{}

	// 1-2. Weighted random selection of the ban fraction.
	toBan := o.selectFraction(o.rng)

	// 3. Move to TempBanned.
	for _, g := range toBan {
		g.SetStatus(classifier.GroupTempBanned, o.nowFn())
		delete(st.AllowedGroups, g.ID)
		st.TempBanned[g.ID] = g
	}
	st.CheckStartStatus = o.checker(o.serviceID)
	st.CycleStart = o.nowFn()
	st.CycleCount++

	// 4. Wait n*2.
	o.sleep(o.wait)

	// 5. Verdict.
	if o.checker(o.serviceID) == CheckerGreen {
		res.Success = true
		for _, g := range st.TempBanned {
			g.SetStatus(classifier.GroupBanned, o.nowFn())
			st.BannedGroups[g.ID] = g
			res.BannedIDs = append(res.BannedIDs, g.ID)
		}
		st.TempBanned = make(map[string]*classifier.FlowGroup)
		// Reset all weights on success.
		for _, g := range st.AllowedGroups {
			g.ResetWeights()
		}
	} else {
		for _, g := range st.TempBanned {
			g.SetStatus(classifier.GroupAllowed, o.nowFn())
			st.AllowedGroups[g.ID] = g
			g.Penalize(0.25)
			res.Restored = append(res.Restored, g.ID)
		}
		st.TempBanned = make(map[string]*classifier.FlowGroup)
		// Recovery: wait another n*2 before the next attempt.
		o.sleep(o.wait)
	}
	return res
}
