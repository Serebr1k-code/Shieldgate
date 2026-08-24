package classifier

import (
	"sync"
	"time"
)

type GroupStatus int8

const (
	GroupCandidate GroupStatus = iota
	GroupAllowed
	GroupBanned
	GroupTempBanned
)

func (s GroupStatus) String() string {
	switch s {
	case GroupAllowed:
		return "allowed"
	case GroupBanned:
		return "banned"
	case GroupTempBanned:
		return "temp_banned"
	default:
		return "candidate"
	}
}

// FlowGroup aggregates flows sharing a fingerprint template.
type FlowGroup struct {
	mu sync.Mutex

	ID          string
	ServiceID   string
	Fingerprint *Fingerprint

	FlowIDs map[string]struct{}
	Count   int

	Weight     float64 // [0.1..1.0], used by weighted random selection
	BaseWeight float64

	Status    GroupStatus
	IsChecker *bool

	FirstSeen time.Time
	LastSeen  time.Time
	BannedAt  *time.Time
}

func NewFlowGroup(id, serviceID string, fp *Fingerprint, now time.Time) *FlowGroup {
	return &FlowGroup{
		ID:          id,
		ServiceID:   serviceID,
		Fingerprint: fp,
		FlowIDs:     make(map[string]struct{}),
		Count:       0,
		Weight:      1.0,
		BaseWeight:  1.0,
		Status:      GroupCandidate,
		FirstSeen:   now,
		LastSeen:    now,
	}
}

func (g *FlowGroup) AddFlow(flowID string, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.FlowIDs[flowID]; !ok {
		g.FlowIDs[flowID] = struct{}{}
		g.Count++
	}
	g.LastSeen = now
}

func (g *FlowGroup) FlowIDList() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]string, 0, len(g.FlowIDs))
	for id := range g.FlowIDs {
		out = append(out, id)
	}
	return out
}

func (g *FlowGroup) SetStatus(s GroupStatus, now time.Time) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Status = s
	if s == GroupBanned {
		t := now
		g.BannedAt = &t
	}
}

func (g *FlowGroup) GetStatus() GroupStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.Status
}

// ResetWeights restores all weights to their base value.
func (g *FlowGroup) ResetWeights() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Weight = g.BaseWeight
}

// Penalize reduces weight by the given fraction (e.g. 0.25 => -25%),
// clamped to a minimum of 0.1.
func (g *FlowGroup) Penalize(fraction float64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.Weight -= fraction * g.Weight
	if g.Weight < 0.1 {
		g.Weight = 0.1
	}
}
