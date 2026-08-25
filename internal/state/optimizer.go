package state

import (
	"math"
	"math/rand"
	"sort"
	"time"

	"shieldgate/internal/board"
	"shieldgate/internal/engine/classifier"
)

// CheckerFunc reports the current checker result for a service.
type CheckerFunc func(serviceID string) board.CheckResult

// SleepFunc pauses for d (injectable in tests).
type SleepFunc func(d time.Duration)

// smallHalfBias is the probability of testing the smaller half first
// (less SLA damage on a red result), the rest of the time — the larger one
// (faster convergence, avoids systematic blind spots).
const smallHalfBias = 0.7

// confirmRedStreak: consecutive red samples required to declare a failure.
const confirmRedStreak = 2

// OptimizerState holds the mutable state of one optimization search.
type OptimizerState struct {
	AllowedGroups map[string]*classifier.FlowGroup
	BannedGroups  map[string]*classifier.FlowGroup
	TempBanned    map[string]*classifier.FlowGroup
	// CriticalGroups: group id -> failure message that proved criticality.
	// Critical groups stay Allowed forever and never re-enter the search.
	CriticalGroups map[string]string

	// Agenda: unproven group-ID sets awaiting a test window.
	Agenda [][]string
	// KnownGroups prevents re-adding groups that already left the agenda.
	KnownGroups map[string]struct{}

	CycleCount       int
	CycleStart       time.Time
	CheckStartStatus board.CheckResult
	LastFailMessage  string

	nowFn func() time.Time
}

func NewOptimizerState(now time.Time, nowFn func() time.Time) *OptimizerState {
	return &OptimizerState{
		AllowedGroups:  make(map[string]*classifier.FlowGroup),
		BannedGroups:   make(map[string]*classifier.FlowGroup),
		TempBanned:     make(map[string]*classifier.FlowGroup),
		CriticalGroups: make(map[string]string),
		Agenda:         nil,
		KnownGroups:    make(map[string]struct{}),
		CycleStart:     now,
		nowFn:          nowFn,
	}
}

// SyncAllowed refreshes sets from the matcher and seeds the agenda with
// newly appeared allowed groups.
func (st *OptimizerState) SyncAllowed(groups []*classifier.FlowGroup) {
	for _, g := range groups {
		if _, critical := st.CriticalGroups[g.ID]; critical {
			continue // proven critical: keep Allowed, never search again
		}
		switch g.GetStatus() {
		case classifier.GroupAllowed:
			if _, banned := st.BannedGroups[g.ID]; banned {
				continue
			}
			st.AllowedGroups[g.ID] = g
			if _, known := st.KnownGroups[g.ID]; !known {
				st.KnownGroups[g.ID] = struct{}{}
				st.Agenda = append(st.Agenda, []string{g.ID})
			}
			if !st.inAgenda(g.ID) {
				st.Agenda = append(st.Agenda, []string{g.ID})
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

func (st *OptimizerState) inAgenda(id string) bool {
	for _, set := range st.Agenda {
		for _, gid := range set {
			if gid == id {
				return true
			}
		}
	}
	return false
}

// weightedSample picks k items without replacement with probability
// proportional to Weight (Efraimidis–Spirakis). Kept for strategy=random.
func weightedSample(items []*classifier.FlowGroup, k int, rng *rand.Rand) []*classifier.FlowGroup {
	type keyed struct {
		g *classifier.FlowGroup
		v float64
	}
	keys := make([]keyed, 0, len(items))
	for _, it := range items {
		w := math.Max(it.Weight, 0.1)
		u := 1 - rng.Float64()
		keys = append(keys, keyed{it, math.Log(u) / w})
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].v > keys[j].v })
	out := make([]*classifier.FlowGroup, 0, k)
	for i := 0; i < k && i < len(keys); i++ {
		out = append(out, keys[i].g)
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// CycleResult summarizes one optimization step (kept for logs/UI).
type CycleResult struct {
	BannedIDs []string
	Restored  []string
	Critical  []string
	FailMsg   string
	Success   bool
}

// OptimizeRunner drives optimization for a single service.
type OptimizeRunner struct {
	state         *OptimizerState
	serviceID     string
	wait          time.Duration // n*2 test window
	banFraction   float64       // legacy random strategy
	checkInterval time.Duration // intra-window polling
	checker       CheckerFunc
	sleep         SleepFunc
	rng           *rand.Rand
	nowFn         func() time.Time

	// recentFailures carries failure signatures seen before the current
	// window (baseline flakiness detection). Maintained by the Manager.
	recentFailures []string
}

func NewOptimizeRunner(state *OptimizerState, serviceID string,
	wait, checkInterval time.Duration,
	checker CheckerFunc, sleep SleepFunc) *OptimizeRunner {
	return &OptimizeRunner{
		state:         state,
		serviceID:     serviceID,
		wait:          wait,
		checkInterval: checkInterval,
		checker:       checker,
		sleep:         sleep,
		rng:           rand.New(rand.NewSource(time.Now().UnixNano())),
		nowFn:         time.Now,
	}
}

func (o *OptimizeRunner) SetClock(f func() time.Time) { o.nowFn = f }
func (o *OptimizeRunner) SetRecentFailures(msgs []string) {
	o.recentFailures = msgs
}

// WaitForGreen blocks until the checker is green or attempts run out.
func (o *OptimizeRunner) WaitForGreen(maxAttempts int) bool {
	for i := 0; i < maxAttempts; i++ {
		if o.checker(o.serviceID).Status.Green() {
			return true
		}
		o.sleep(o.checkInterval)
	}
	return o.checker(o.serviceID).Status.Green()
}

// ---- binary search engine ----

type chunkVerdict struct {
	failed  bool
	failMsg string
	aborted bool // failed fast before window end
}

// hasBaselineSignature reports whether msg was already seen as a failure
// before this window (background flakiness, not caused by our ban).
func (o *OptimizeRunner) hasBaselineSignature(msg string) bool {
	if msg == "" {
		return false
	}
	for _, m := range o.recentFailures {
		if m == msg {
			return true
		}
	}
	return false
}

// testChunk temporarily bans the chunk and watches the checker for the full
// window with early abort on confirmed failures.
func (o *OptimizeRunner) testChunk(chunk []*classifier.FlowGroup) chunkVerdict {
	for _, g := range chunk {
		g.SetStatus(classifier.GroupTempBanned, o.nowFn())
		o.state.TempBanned[g.ID] = g
		delete(o.state.AllowedGroups, g.ID)
	}
	start := o.checker(o.serviceID)
	st := o.state
	st.CheckStartStatus = start
	st.CycleCount++

	redStreak := 0
	lastMsg := ""
	elapsed := time.Duration(0)
	for elapsed < o.wait {
		o.sleep(o.checkInterval)
		elapsed += o.checkInterval
		res := o.checker(o.serviceID)
		if res.Status.Green() || res.Status == CheckerUnknown {
			redStreak = 0
			continue
		}
		// Red sample: ignore messages identical to pre-existing baseline
		// failures (background flakiness), count everything else.
		if o.hasBaselineSignature(res.Message) && lastMsg == "" {
			continue
		}
		redStreak++
		lastMsg = res.Message
		if redStreak >= confirmRedStreak {
			return chunkVerdict{failed: true, failMsg: lastMsg, aborted: elapsed < o.wait}
		}
	}

	final := o.checker(o.serviceID)
	if final.Status.Red() && !o.hasBaselineSignature(final.Message) {
		return chunkVerdict{failed: true, failMsg: final.Message}
	}
	return chunkVerdict{}
}

func (o *OptimizeRunner) restoreChunk(chunk []*classifier.FlowGroup, msg string, res *CycleResult) {
	for _, g := range chunk {
		g.SetStatus(classifier.GroupAllowed, o.nowFn())
		o.state.AllowedGroups[g.ID] = g
		delete(o.state.TempBanned, g.ID)
		res.Restored = append(res.Restored, g.ID)
	}
	if msg != "" {
		o.state.LastFailMessage = msg
		res.FailMsg = msg
	}
}

func (o *OptimizeRunner) banChunk(chunk []*classifier.FlowGroup, res *CycleResult) {
	for _, g := range chunk {
		g.SetStatus(classifier.GroupBanned, o.nowFn())
		o.state.BannedGroups[g.ID] = g
		delete(o.state.TempBanned, g.ID)
		delete(o.state.AllowedGroups, g.ID)
		res.BannedIDs = append(res.BannedIDs, g.ID)
	}
}

// markCritical records a proven-critical group: stays Allowed forever,
// excluded from further search.
func (o *OptimizeRunner) markCritical(g *classifier.FlowGroup, msg string, res *CycleResult) {
	v := true
	g.IsChecker = &v
	g.SetStatus(classifier.GroupAllowed, o.nowFn())
	o.state.CriticalGroups[g.ID] = msg
	o.state.AllowedGroups[g.ID] = g
	delete(o.state.TempBanned, g.ID)
	res.Critical = append(res.Critical, g.ID)
	if msg != "" {
		res.FailMsg = msg
	}
}

// split halves a chunk; smaller half first with probability smallHalfBias.
func (o *OptimizeRunner) split(ids []string) (a, b []string) {
	sort.Strings(ids)
	mid := len(ids) / 2
	small, large := ids[:mid], ids[mid:]
	if len(small) == 0 { // odd count: move boundary so both non-empty
		small, large = ids[:1], ids[1:]
	}
	if o.rng.Float64() < smallHalfBias {
		return small, large
	}
	return large, small
}

func (o *OptimizeRunner) resolve(ids []string) []*classifier.FlowGroup {
	var out []*classifier.FlowGroup
	for _, id := range ids {
		if g, ok := o.state.AllowedGroups[id]; ok {
			if _, critical := o.state.CriticalGroups[id]; !critical {
				out = append(out, g)
			}
		}
	}
	return out
}

// RunSearch executes binary splitting until the agenda is exhausted.
func (o *OptimizeRunner) RunSearch() CycleResult {
	total := CycleResult{Success: true}
	for len(o.state.Agenda) > 0 {
		item := o.state.Agenda[0]
		o.state.Agenda = o.state.Agenda[1:]

		chunk := o.resolve(item)
		if len(chunk) == 0 {
			continue
		}

		step := CycleResult{}
		if len(chunk) == 1 {
			g := chunk[0]
			verdict := o.testChunk([]*classifier.FlowGroup{g})
			if verdict.failed {
				o.markCritical(g, verdict.failMsg, &step)
			} else {
				o.banChunk([]*classifier.FlowGroup{g}, &step)
			}
		} else {
			aIDs, bIDs := o.split(idsOf(chunk))
			a := resolveByID(o.state, aIDs)
			verdict := o.testChunk(a)
			if verdict.failed {
				o.restoreChunk(a, verdict.failMsg, &step)
				// recurse into A's halves; B remains unproven too.
				h1, h2 := o.split(aIDs)
				o.state.Agenda = append(o.state.Agenda, h1, h2, bIDs)
			} else {
				o.banChunk(a, &step)
				o.state.Agenda = append(o.state.Agenda, bIDs)
			}
		}

		mergeResults(&total, step)
	}
	return total
}

func idsOf(groups []*classifier.FlowGroup) []string {
	out := make([]string, 0, len(groups))
	for _, g := range groups {
		out = append(out, g.ID)
	}
	return out
}

func resolveByID(st *OptimizerState, ids []string) []*classifier.FlowGroup {
	var out []*classifier.FlowGroup
	for _, id := range ids {
		if g, ok := st.AllowedGroups[id]; ok {
			if _, critical := st.CriticalGroups[id]; !critical {
				out = append(out, g)
			}
		}
	}
	return out
}

func mergeResults(total *CycleResult, step CycleResult) {
	total.BannedIDs = append(total.BannedIDs, step.BannedIDs...)
	total.Restored = append(total.Restored, step.Restored...)
	total.Critical = append(total.Critical, step.Critical...)
	if step.FailMsg != "" {
		total.FailMsg = step.FailMsg
		total.Success = false
	}
}

// ---- legacy weighted-random strategy (optimize.strategy = "random") ----

// SelectForTempBan chooses ~fraction of allowed groups via weighted random.
// Groups marked IsChecker=true or proven critical are excluded.
func (o *OptimizeRunner) SelectForTempBan(rng *rand.Rand) []*classifier.FlowGroup {
	var candidates []*classifier.FlowGroup
	for _, g := range o.state.AllowedGroups {
		if g.IsChecker != nil && *g.IsChecker {
			continue
		}
		if _, critical := o.state.CriticalGroups[g.ID]; critical {
			continue
		}
		candidates = append(candidates, g)
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

// RunCycle executes one legacy 1/4-ban cycle.
func (o *OptimizeRunner) RunCycle() CycleResult {
	st := o.state
	res := CycleResult{}

	toBan := o.SelectForTempBan(o.rng)
	for _, g := range toBan {
		g.SetStatus(classifier.GroupTempBanned, o.nowFn())
		delete(st.AllowedGroups, g.ID)
		st.TempBanned[g.ID] = g
	}
	st.CheckStartStatus = o.checker(o.serviceID)
	st.CycleStart = o.nowFn()
	st.CycleCount++

	o.sleep(o.wait)

	if o.checker(o.serviceID).Status.Green() {
		res.Success = true
		for _, g := range st.TempBanned {
			g.SetStatus(classifier.GroupBanned, o.nowFn())
			st.BannedGroups[g.ID] = g
			res.BannedIDs = append(res.BannedIDs, g.ID)
		}
		st.TempBanned = make(map[string]*classifier.FlowGroup)
		for _, g := range st.AllowedGroups {
			g.ResetWeights()
		}
	} else {
		msg := o.checker(o.serviceID).Message
		for _, g := range st.TempBanned {
			g.SetStatus(classifier.GroupAllowed, o.nowFn())
			st.AllowedGroups[g.ID] = g
			g.Penalize(0.25)
			res.Restored = append(res.Restored, g.ID)
		}
		st.TempBanned = make(map[string]*classifier.FlowGroup)
		if msg != "" {
			res.FailMsg = msg
			st.LastFailMessage = msg
		}
		o.sleep(o.wait) // recovery window
	}
	return res
}

func (o *OptimizeRunner) SetBanFraction(f float64) { o.banFraction = f }
