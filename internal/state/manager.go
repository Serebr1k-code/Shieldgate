package state

import (
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

	cfg     *config.Config
	client  board.BoardClient
	flags   *FlagDetector
	checker map[string]CheckerStatus

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
		services: make(map[string]*Service),
		cfg:      cfg,
		client:   client,
		flags:    fd,
		checker:  make(map[string]CheckerStatus),
		nowFn:    time.Now,
		stop:     make(chan struct{}),
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
	statuses, err := m.client.Poll()
	if err != nil {
		log.Printf("board poll error: %v", err)
		return
	}
	for id, st := range statuses {
		m.setChecker(id, st)
		m.broadcast(Event{Type: "checker.update", ServiceID: id, Message: st.String(), At: m.nowFn()})
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

// runOptimizer loops optimization cycles until stopped or phase changes.
func (m *Manager) runOptimizer(s *Service) {
	opt := s.Opt()
	if opt == nil {
		return
	}
	opt.SyncAllowed(s.Matcher.ForService(s.ID))
	runner := NewOptimizeRunner(opt, s.ID, s.BanFraction, s.RoundDuration*2,
		func(id string) CheckerStatus { return m.CheckerStatus(id) },
		time.Sleep)
	if !runner.WaitForGreen(3) {
		return // stay in optimizing phase; next poll retries
	}
	res := runner.RunCycle()
	log.Printf("optimizer cycle for %s: success=%v banned=%v restored=%v",
		s.ID, res.Success, res.BannedIDs, res.Restored)
}
