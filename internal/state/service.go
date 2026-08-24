package state

import (
	"sync"
	"time"

	"shieldgate/internal/engine/classifier"
)

type ServicePhase int8

const (
	PhaseIdle ServicePhase = iota
	PhaseLearning
	PhaseFiltering
	PhaseOptimizing
)

func (p ServicePhase) String() string {
	switch p {
	case PhaseLearning:
		return "learning"
	case PhaseFiltering:
		return "filtering"
	case PhaseOptimizing:
		return "optimizing"
	default:
		return "idle"
	}
}

// Service is a single protected service on our team.
type Service struct {
	mu sync.RWMutex

	ID   string
	Name string

	Port     uint16
	Protocol string // "tcp" | "udp"

	// Grouping state (owned by classifier).
	Matcher *classifier.Matcher

	// Learning / optimization.
	RoundDuration time.Duration
	BanFraction   float64
	FlagRegexStr  string

	phase   ServicePhase
	opt     *OptimizerState
	nowFn   func() time.Time
	onEvent func(ev Event)
}

// Event is emitted on service lifecycle changes (for API/WS broadcast).
type Event struct {
	Type      string // phase.change | learning.reset | groups.allowed ...
	ServiceID string
	Message   string
	At        time.Time
}

func NewService(id, name string, port uint16, protocol string, roundDuration time.Duration, banFraction float64) *Service {
	return &Service{
		ID:            id,
		Name:          name,
		Port:          port,
		Protocol:      protocol,
		Matcher:       classifier.NewMatcher(),
		RoundDuration: roundDuration,
		BanFraction:   banFraction,
		FlagRegexStr:  DefaultFlagRegex,
		phase:         PhaseIdle,
		nowFn:         time.Now,
	}
}

func (s *Service) SetClock(f func() time.Time) {
	s.nowFn = f
	if s.opt != nil {
		s.opt.nowFn = f
	}
}

func (s *Service) OnEvent(f func(Event)) { s.onEvent = f }

func (s *Service) emit(typ, msg string) {
	if s.onEvent == nil {
		return
	}
	s.onEvent(Event{Type: typ, ServiceID: s.ID, Message: msg, At: s.nowFn()})
}

func (s *Service) Phase() ServicePhase {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.phase
}

func (s *Service) setPhase(p ServicePhase) {
	s.mu.Lock()
	s.phase = p
	s.mu.Unlock()
	s.emit("phase.change", p.String())
}

// StartLearning begins the learning window (n*2). Checker gating is done by
// the caller (Manager), which only calls this once the checker is green.
func (s *Service) StartLearning() {
	s.setPhase(PhaseLearning)
	s.emit("learning.start", "collecting legitimate traffic")
}

// ResetLearning drops all candidate groups and restarts collection.
func (s *Service) ResetLearning() {
	for _, g := range s.Matcher.ForService(s.ID) {
		if g.GetStatus() == classifier.GroupCandidate {
			g.SetStatus(classifier.GroupBanned, s.nowFn()) // archive as banned? no: drop
		}
	}
	s.emit("learning.reset", "checker failed during learning; restarting")
	s.StartLearning()
}

// FinishLearning promotes all candidate groups to Allowed.
func (s *Service) FinishLearning() {
	now := s.nowFn()
	for _, g := range s.Matcher.ForService(s.ID) {
		if g.GetStatus() == classifier.GroupCandidate {
			g.SetStatus(classifier.GroupAllowed, now)
			g.ResetWeights()
		}
	}
	s.mu.Lock()
	s.opt = NewOptimizerState(now, s.nowFn)
	s.mu.Unlock()
	s.setPhase(PhaseFiltering)
	s.emit("groups.allowed", "learning finished")
}

// Opt returns the current optimizer state or nil.
func (s *Service) Opt() *OptimizerState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.opt
}

// StartOptimization switches the service into the optimizing phase.
func (s *Service) StartOptimization() { s.setPhase(PhaseOptimizing) }
