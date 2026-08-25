package state

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/board"
	"shieldgate/internal/engine/classifier"
)

// ---- helpers ----

type fakeChecker struct {
	mu      syncMap
	results map[string]board.CheckResult
}

type syncMap struct{ m map[string]board.CheckResult }

func newFakeChecker(initial map[string]board.CheckResult) *fakeChecker {
	if initial == nil {
		initial = map[string]board.CheckResult{}
	}
	return &fakeChecker{results: initial}
}

func (f *fakeChecker) set(svc string, res board.CheckResult) {
	f.results[svc] = res
}

func (f *fakeChecker) __() {}

// checkerFunc returns a CheckerFunc reading current results.
func (f *fakeChecker) checkerFunc() CheckerFunc {
	return func(svc string) board.CheckResult { return f.results[svc] }
}

// recordingSleep counts total simulated time and supports hooks per call.
type recordingSleep struct {
	total time.Duration
	calls []time.Duration
}

func (r *recordingSleep) sleep(d time.Duration) {
	r.total += d
	r.calls = append(r.calls, d)
}

func green(msg string) board.CheckResult {
	return board.CheckResult{Status: CheckerGreen, Message: msg}
}
func red(msg string) board.CheckResult { return board.CheckResult{Status: CheckerRed, Message: msg} }
func unknown() board.CheckResult       { return board.CheckResult{Status: CheckerUnknown} }

func seedAllowedGroups(t *testing.T, st *OptimizerState, n int) []*classifier.FlowGroup {
	t.Helper()
	groups := make([]*classifier.FlowGroup, 0, n)
	for i := 0; i < n; i++ {
		fp := classifier.NewFingerprint([]byte(fmt.Sprintf("shape-%d", i)))
		g := classifier.NewFlowGroup(fmt.Sprintf("g%d", i), "svc", fp, time.Now())
		g.SetStatus(classifier.GroupAllowed, time.Now())
		st.AllowedGroups[g.ID] = g
		st.KnownGroups[g.ID] = struct{}{}
		groups = append(groups, g)
	}
	var ids []string
	for _, g := range groups {
		ids = append(ids, g.ID)
	}
	st.Agenda = append(st.Agenda, ids)
	return groups
}

func findCriticalByMark(groups []*classifier.FlowGroup) *classifier.FlowGroup {
	for _, g := range groups {
		if g.IsChecker != nil && *g.IsChecker {
			return g
		}
	}
	return nil
}

// ---- tests ----

func TestBinarySearchFindsSingleCritical(t *testing.T) {
	st := NewOptimizerState(time.Now(), time.Now)
	groups := seedAllowedGroups(t, st, 8)
	critical := groups[3].ID // exactly one critical group

	chk := newFakeChecker(map[string]board.CheckResult{"svc": green("")})
	sleep := &recordingSleep{}
	runner := NewOptimizeRunner(st, "svc", 10*time.Second, time.Second,
		func(svc string) board.CheckResult {
			res := chk.results[svc]
			// Simulate: checker red iff any banned group is the critical one.
			if res.Status.Red() {
				return res
			}
			for _, g := range groups {
				if g.ID == critical && st.TempBanned[g.ID] != nil {
					return red("Could not get flag")
				}
			}
			return green("")
		},
		sleep.sleep)

	res := runner.RunSearch()

	require.NotEmpty(t, res.Critical, "critical group must be found")
	assert.Equal(t, []string{critical}, res.Critical)

	found := findCriticalByMark(groups)
	require.NotNil(t, found)
	assert.Equal(t, critical, found.ID)
	assert.Equal(t, classifier.GroupAllowed, found.GetStatus(),
		"critical group must stay allowed")

	banned := 0
	for _, g := range groups {
		if g.ID == critical {
			continue
		}
		require.Equal(t, classifier.GroupBanned, g.GetStatus(),
			"group %s must be banned", g.ID)
		banned++
	}
	assert.Equal(t, 7, banned)
	assert.Empty(t, st.Agenda, "agenda must be exhausted")

	// Convergence budget: log2(8)=3 splits; each green window costs
	// wait/checkInterval=10 polls. Allow generous slack but catch blowups.
	// Windows are bounded by the recursion tree size (~2N worst case),
	// far better than unbounded random cycles.
	assert.LessOrEqual(t, st.CycleCount, 16,
		"must stay within recursion-tree budget, got %d", st.CycleCount)
	assert.LessOrEqual(t, len(sleep.calls), 160, "sanity cap on total polling")
}

func TestBinarySearchMultipleCriticals(t *testing.T) {
	st := NewOptimizerState(time.Now(), time.Now)
	groups := seedAllowedGroups(t, st, 8)
	criticals := map[string]bool{groups[1].ID: true, groups[6].ID: true}

	runner := NewOptimizeRunner(st, "svc", 5*time.Second, time.Second,
		func(svc string) board.CheckResult {
			for id := range criticals {
				if st.TempBanned[id] != nil {
					return red("Could not get flag")
				}
			}
			return green("")
		},
		func(d time.Duration) {})

	res := runner.RunSearch()
	assert.Len(t, res.Critical, 2, "both critical groups must be isolated")

	for _, g := range groups {
		if criticals[g.ID] {
			assert.Equal(t, classifier.GroupAllowed, g.GetStatus())
			assert.Contains(t, st.CriticalGroups, g.ID)
		} else {
			assert.Equal(t, classifier.GroupBanned, g.GetStatus())
		}
	}
}

func TestFlakyKnownMessageIgnored(t *testing.T) {
	st := NewOptimizerState(time.Now(), time.Now)
	groups := seedAllowedGroups(t, st, 4)

	runner := NewOptimizeRunner(st, "svc", 8*time.Second, time.Second,
		func(svc string) board.CheckResult { return red("Checker timed out") },
		func(time.Duration) {})
	// Baseline: this exact failure was seen before our ban.
	runner.SetRecentFailures([]string{"Checker timed out"})

	res := runner.RunSearch()

	assert.Empty(t, res.Restored, "known-flaky message must not count as failure")
	assert.Empty(t, res.Critical)
	for _, g := range groups {
		assert.Equal(t, classifier.GroupBanned, g.GetStatus(),
			"all groups bannable when checker noise matches baseline")
	}
}

func TestNewFailureMessageTriggersFailFast(t *testing.T) {
	st := NewOptimizerState(time.Now(), time.Now)
	groups := seedAllowedGroups(t, st, 4)

	sleep := &recordingSleep{}
	runner := NewOptimizeRunner(st, "svc", 60*time.Second, 5*time.Second,
		func(svc string) board.CheckResult { return red("Could not get flag") },
		sleep.sleep)

	res := runner.RunSearch()
	// Persistent red with empty baseline => every group proves critical.
	assert.Len(t, res.Critical, 4)
	assert.Contains(t, res.Critical, groups[0].ID)

	// Fail-fast: two consecutive red samples at 5s interval, not full 60s.
	maxSpent := time.Duration(0)
	for _, c := range sleep.calls {
		if c > maxSpent {
			maxSpent = time.Duration(int64(c))
		}
	}
	totalPerWindow := sum(sleep.calls) / int64(len(res.Critical)+len(res.BannedIDs)+len(res.Restored))
	assert.Less(t, time.Duration(totalPerWindow), 60*time.Second,
		"window must abort early on confirmed failure")
	_ = maxSpent
}

func TestSmallerHalfBias(t *testing.T) {
	ids := make([]string, 9)
	for i := range ids {
		ids[i] = fmt.Sprintf("g%d", i)
	}
	st := NewOptimizerState(time.Now(), time.Now)
	runner := NewOptimizeRunner(st, "svc", time.Second, time.Second,
		func(string) board.CheckResult { return green("") }, func(time.Duration) {})

	smallerFirst := 0
	trials := 2000
	for i := 0; i < trials; i++ {
		a, b := runner.split(ids)
		if len(a) < len(b) {
			smallerFirst++
		} else if len(a) == len(b) {
			smallerFirst++ // equal halves: either is fine, don't skew stats
		}
	}
	ratio := float64(smallerFirst) / float64(trials)
	assert.Greater(t, ratio, 0.55, "smaller half must be preferred most of the time")
	assert.Less(t, ratio, 0.85, "...but not always")
}

func TestCriticalExcludedFromFutureSearches(t *testing.T) {
	st := NewOptimizerState(time.Now(), time.Now)
	groups := seedAllowedGroups(t, st, 4)

	require.Len(t, groups, 4)
	st.CriticalGroups[groups[0].ID] = "Could not get flag"
	v := true
	groups[0].IsChecker = &v
	st.SyncAllowed(groups) // re-sync must not re-add critical to agenda

	// The engine resolves agenda items through resolve(), which must skip
	// critical groups even if stale references remain.
	runner := NewOptimizeRunner(st, "svc", time.Second, time.Second,
		func(string) board.CheckResult { return green("") }, func(time.Duration) {})
	var flat []string
	for _, set := range st.Agenda {
		flat = append(flat, set...)
	}
	resolved := runner.resolve(flat)
	for _, g := range resolved {
		assert.NotEqual(t, groups[0].ID, g.ID, "critical group must never resolve into a test chunk")
	}
	assert.NotNil(t, st.AllowedGroups[groups[0].ID],
		"critical group traffic stays allowed")
}

func TestLegacyRandomCycleStillWorks(t *testing.T) {
	st := NewOptimizerState(time.Now(), time.Now)
	groups := seedAllowedGroups(t, st, 8)
	require.Len(t, groups, 8)

	cycle := 0
	runner := NewOptimizeRunner(st, "svc", time.Second, time.Second,
		func(svc string) board.CheckResult {
			cycle++
			if cycle == 1 {
				return green("")
			}
			return red("boom")
		}, func(time.Duration) {})
	runner.SetBanFraction(0.25)

	res := runner.RunCycle()
	assert.False(t, res.Success)
	assert.Len(t, res.Restored, 2) // floor(8*0.25)=2
}

func sum(vals []time.Duration) int64 {
	var s int64
	for _, v := range vals {
		s += int64(v)
	}
	return s
}

var _ = unknown
