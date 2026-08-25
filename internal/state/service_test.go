package state

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"shieldgate/internal/board"
	"shieldgate/internal/engine/classifier"
)

func newTestService(t *testing.T) *Service {
	s := NewService("svc1", "test", 5000, "tcp", time.Minute, 0.5)
	var events []Event
	s.OnEvent(func(e Event) { events = append(events, e) })
	return s
}

func (s *Service) seedGroups(t *testing.T, n int) []*classifier.FlowGroup {
	groups := make([]*classifier.FlowGroup, 0, n)
	for i := 0; i < n; i++ {
		fp := classifier.NewFingerprint([]byte{byte('A' + i)})
		g := s.Matcher.FindOrCreateGroup(s.ID, fp, "flow"+string(rune('a'+i)))
		g.SetStatus(classifier.GroupAllowed, time.Now())
		groups = append(groups, g)
	}
	return groups
}

func TestLearningPhaseLifecycle(t *testing.T) {
	now := time.Now()
	s := newTestService(t)
	s.SetClock(func() time.Time { return now })
	require.Equal(t, PhaseIdle, s.Phase())

	// Checker green -> learning starts.
	s.StartLearning()
	assert.Equal(t, PhaseLearning, s.Phase())

	// Collect traffic: two legit shapes + one exploit shape.
	for i := 0; i < 3; i++ {
		s.Matcher.FindOrCreateGroup(s.ID, classifier.NewFingerprint([]byte("GET /status HTTP/1.1")), "f1")
		s.Matcher.FindOrCreateGroup(s.ID, classifier.NewFingerprint([]byte("GET /info HTTP/1.1")), "f2")
		s.Matcher.FindOrCreateGroup(s.ID, classifier.NewFingerprint([]byte("POST /exploit HTTP/1.1")), "f3")
	}
	require.Equal(t, 3, s.Matcher.Count())

	// Learning window ends with green checker -> all candidates Allowed.
	s.FinishLearning()
	assert.Equal(t, PhaseFiltering, s.Phase())
	for _, g := range s.Matcher.ForService(s.ID) {
		assert.Equal(t, classifier.GroupAllowed, g.GetStatus(), "group %s must be allowed", g.ID)
		assert.InDelta(t, 1.0, g.Weight, 1e-9)
	}
	require.NotNil(t, s.Opt())
}

func TestOptimizerSuccessScenario(t *testing.T) {
	now := time.Now()
	s := newTestService(t)
	groups := s.seedGroups(t, 8)
	st := NewOptimizerState(now, func() time.Time { return now })
	st.SyncAllowed(groups)

	checkerGreen := true
	waits := 0
	r := NewOptimizeRunner(st, s.ID, 10*time.Second, time.Second,
		func(string) board.CheckResult {
			if checkerGreen {
				return green("")
			}
			return red("boom")
		},
		func(d time.Duration) { waits++; now = now.Add(d) })
	r.SetBanFraction(0.25)

	res := r.RunCycle()
	require.True(t, res.Success)
	require.Len(t, res.BannedIDs, 2, "25% of 8 groups")
	assert.Equal(t, 1, waits)

	banned := 0
	for _, g := range groups {
		switch g.GetStatus() {
		case classifier.GroupBanned:
			banned++
		case classifier.GroupAllowed:
			assert.InDelta(t, 1.0, g.Weight, 1e-9, "weights reset on success")
		}
	}
	assert.Equal(t, 2, banned)
}

func TestOptimizerFailureScenario(t *testing.T) {
	now := time.Now()
	s := newTestService(t)
	groups := s.seedGroups(t, 4)
	st := NewOptimizerState(now, func() time.Time { return now })
	st.SyncAllowed(groups)

	cycle := 0
	r := NewOptimizeRunner(st, s.ID, 10*time.Second, time.Second,
		func(string) board.CheckResult {
			cycle++
			if cycle == 1 { // green at selection, red after wait
				return green("")
			}
			return red("boom")
		},
		func(d time.Duration) { now = now.Add(d) })
	r.SetBanFraction(0.25)

	res := r.RunCycle()
	require.False(t, res.Success)
	require.Len(t, res.Restored, 1)
	assert.Equal(t, 1, len(res.BannedIDs)+len(res.Restored), "25% of 4 groups")

	for _, g := range groups {
		status := g.GetStatus()
		if status == classifier.GroupBanned {
			continue
		}
		assert.Equal(t, classifier.GroupAllowed, status)
	}
}

func TestOptimizerCheckerMarkedExcluded(t *testing.T) {
	now := time.Now()
	s := newTestService(t)
	groups := s.seedGroups(t, 4)
	// Mark all as checker traffic -> nothing may be banned.
	for _, g := range groups {
		v := true
		g.IsChecker = &v
	}
	st := NewOptimizerState(now, func() time.Time { return now })
	st.SyncAllowed(groups)

	r := NewOptimizeRunner(st, s.ID, time.Second, time.Second,
		func(string) board.CheckResult { return green("") },
		func(time.Duration) {})
	r.SetBanFraction(0.25)
	res := r.RunCycle()
	assert.True(t, res.Success)
	assert.Empty(t, res.BannedIDs)
	assert.Empty(t, res.Restored)
}

func TestWeightedSampleRespectsWeights(t *testing.T) {
	now := time.Now()
	heavy := NewFlowGroupFixture("heavy", 100.0, now) // weight 100
	light := NewFlowGroupFixture("light", 0.1, now)   // weight 0.1

	pickedHeavy, pickedLight := 0, 0
	for i := 0; i < 2000; i++ {
		out := weightedSample([]*classifier.FlowGroup{heavy, light}, 1,
			newSeededRand(i))
		if out[0].ID == "heavy" {
			pickedHeavy++
		} else {
			pickedLight++
		}
	}
	assert.Greater(t, pickedHeavy, pickedLight*5, "heavy group must dominate picks")
}
