package state

import (
	"fmt"
	"log"
	"sync"
	"time"

	"shieldgate/internal/board"
	"shieldgate/internal/config"
)

// Manager owns all services, drives the board poller and phase transitions.
type Manager struct {
	mu       sync.RWMutex
	services map[string]*Service

	cfg          *config.Config
	client       board.BoardClient
	flags        *FlagDetector
	checker      map[string]CheckerStatus
	checkDetails map[string]board.CheckResult
	failureSigs  map[string][]string

	nowFn   func() time.Time
	stop    chan struct{}
	onEvent func(Event)
}

func NewManager(cfg *config.Config, client board.BoardClient) (*Manager, error) {
	fd, err := NewFlagDetector(cfg.Learn.FlagRegex)
	if err != nil {
		return nil, err
	}
	return &Manager{
		services:     make(map[string]*Service),
		cfg:          cfg,
		client:       client,
		flags:        fd,
		checker:      make(map[string]CheckerStatus),
		checkDetails: make(map[string]board.CheckResult),
		failureSigs:  make(map[string][]string),
		nowFn:        time.Now,
		stop:         make(chan struct{}),
	}, nil
}

// OnEvent registers a listener for service lifecycle events.
func (m *Manager) OnEvent(f func(Event)) { m.onEvent = f }

// SetClient swaps the board client at runtime (used by reconfiguration).
func (m *Manager) SetClient(c board.BoardClient) {
	m.mu.Lock()
	m.client = c
	m.mu.Unlock()
}

// SetFlagPattern updates the flag detection regex at runtime.
func (m *Manager) SetFlagPattern(pattern string) error { return m.flags.SetPattern(pattern) }

func (m *Manager) broadcast(ev Event) {
	if m.onEvent != nil {
		m.onEvent(ev)
	}
}

func (m *Manager) SetClock(f func() time.Time) { m.nowFn = f }

func (m *Manager) FlagDetector() *FlagDetector { return m.flags }

// SyncServices creates/updates services from the board listing.
func (m *Manager) SyncServices(infos []board.ServiceInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, info := range infos {
		if s, ok := m.services[info.ID]; ok {
			s.Port = info.Port
			continue
		}
		s := NewService(info.ID, info.Name, info.Port, info.Protocol,
			m.cfg.Learn.RoundDuration, m.cfg.Optimize.BanFraction)
		m.services[info.ID] = s
	}
}

func (m *Manager) Get(id string) (*Service, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.services[id]
	return s, ok
}

func (m *Manager) All() []*Service {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Service, 0, len(m.services))
	for _, s := range m.services {
		out = append(out, s)
	}
	return out
}

func (m *Manager) CheckerStatus(serviceID string) CheckerStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.checker[serviceID]
}

// rememberFailure keeps the last few distinct failure messages per service
// as baseline signatures for flakiness detection in the optimizer.
func (m *Manager) rememberFailure(serviceID, msg string) {
	if msg == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	list := m.failureSigs[serviceID]
	for _, existing := range list {
		if existing == msg {
			return
		}
	}
	list = append(list, msg)
	if len(list) > 5 {
		list = list[len(list)-5:]
	}
	m.failureSigs[serviceID] = list
}

func (m *Manager) recentFailures(serviceID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.failureSigs[serviceID]...)
}

func (m *Manager) setChecker(id string, st CheckerStatus) {
	m.mu.Lock()
	prev := m.checker[id]
	m.checker[id] = st
	m.mu.Unlock()
	if prev != st {
		log.Printf("checker %s -> %s", id, st)
	}
}

// ServiceForPort finds the service listening on a given TCP port.
func (m *Manager) ServiceForPort(port uint16) (*Service, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.services {
		if s.Port == port {
			return s, true
		}
	}
	return nil, false
}

// StartPolling polls the board on an interval and advances service phases:
//
//	green checker + Idle/Learning-restart  -> Learning window -> FinishLearning
//	red during Learning                    -> ResetLearning
//	Filtering                              -> Optimization cycles
func (m *Manager) StartPolling(interval time.Duration) {
	go func() {
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-m.stop:
				return
			case <-t.C:
				m.pollOnce()
			}
		}
	}()
}

func (m *Manager) Stop() { close(m.stop) }

func (m *Manager) pollOnce() {
	m.mu.RLock()
	client := m.client
	m.mu.RUnlock()
	if client == nil {
		return // no board connected yet (awaiting UI configuration)
	}
	details, err := board.PollDetailedOf(client)
	if err != nil {
		log.Printf("board poll error: %v", err)
		return
	}
	m.mu.Lock()
	for id, res := range details {
		m.checker[id] = res.Status
		m.checkDetails[id] = res
	}
	m.mu.Unlock()
	for id, res := range details {
		m.setChecker(id, res.Status)
		msg := res.Status.String()
		if res.Message != "" && res.Status.Red() {
			msg += ": " + res.Message
			m.rememberFailure(id, res.Message)
		}
		m.broadcast(Event{Type: "checker.update", ServiceID: id, Message: msg, At: m.nowFn()})
	}

	m.mu.RLock()
	services := make([]*Service, 0, len(m.services))
	for _, s := range m.services {
		services = append(services, s)
	}
	m.mu.RUnlock()

	for _, s := range services {
		st := m.CheckerStatus(s.ID)
		switch s.Phase() {
		case PhaseIdle, PhaseLearning:
			if st == CheckerGreen && s.Phase() == PhaseIdle {
				s.StartLearning()
				m.scheduleLearningEnd(s)
			} else if st == CheckerRed && s.Phase() == PhaseLearning {
				s.ResetLearning()
				m.scheduleLearningEnd(s)
			}
		case PhaseFiltering:
			if st != CheckerGreen {
				continue // wait for green before optimizing
			}
			s.StartOptimization()
			go m.runOptimizer(s)
		}
	}
}

// scheduleLearningEnd finishes learning after n*2 unless reset happened.
func (m *Manager) scheduleLearningEnd(s *Service) {
	window := s.RoundDuration * 2
	startedAt := m.nowFn()
	go func() {
		t := time.NewTicker(window)
		defer t.Stop()
		select {
		case <-m.stop:
			return
		case <-t.C:
		}
		if m.nowFn().Sub(startedAt) >= window-(intervalSlack) && s.Phase() == PhaseLearning && m.CheckerStatus(s.ID) == CheckerGreen {
			s.FinishLearning()
		}
	}()
}

const intervalSlack = time.Second

// runOptimizer drives the configured strategy until its agenda is exhausted
// or the checker goes red outside a controlled test.
func (m *Manager) runOptimizer(s *Service) {
	opt := s.Opt()
	if opt == nil {
		return
	}
	opt.SyncAllowed(s.Matcher.ForService(s.ID))

	strategy := m.cfg.Optimize.Strategy
	if strategy == "" {
		strategy = "binary"
	}
	runner := NewOptimizeRunner(opt, s.ID,
		s.RoundDuration*2, m.cfg.Optimize.CheckInterval,
		func(id string) board.CheckResult {
			m.mu.RLock()
			defer m.mu.RUnlock()
			if res, ok := m.checkDetails[id]; ok {
				return res
			}
			return board.CheckResult{Status: m.checker[id]}
		},
		time.Sleep)
	if !runner.WaitForGreen(3) {
		return // stay in optimizing phase; next poll retries
	}

	var res CycleResult
	switch strategy {
	case "random":
		runner.SetBanFraction(s.BanFraction)
		res = runner.RunCycle()
	default: // binary
		runner.SetRecentFailures(m.recentFailures(s.ID))
		res = runner.RunSearch()
	}
	log.Printf("optimizer (%s) for %s: banned=%v critical=%v restored=%v fail=%q",
		strategy, s.ID, res.BannedIDs, res.Critical, res.Restored, res.FailMsg)
	for _, gid := range res.Critical {
		m.broadcast(Event{Type: "optimizer.critical", ServiceID: s.ID,
			Message: fmt.Sprintf("group %s marked critical (%s)", short(gid), res.FailMsg),
			At:      m.nowFn()})
	}
}

func short(id string) string {
	if len(id) > 10 {
		return id[:10]
	}
	return id
}
