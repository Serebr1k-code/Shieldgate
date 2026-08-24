package classifier

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

const SimilarityThreshold = 0.85

// Matcher assigns flows to FlowGroups by fingerprint
// (exact hash first, then fuzzy match).
type Matcher struct {
	mu         sync.Mutex
	groups     map[string]*FlowGroup // id -> group
	exactIndex map[[32]byte]string   // fingerprint hash -> group id
	nowFn      func() time.Time
}

func NewMatcher() *Matcher {
	return &Matcher{
		groups:     make(map[string]*FlowGroup),
		exactIndex: make(map[[32]byte]string),
		nowFn:      time.Now,
	}
}

func (m *Matcher) SetClock(f func() time.Time) { m.nowFn = f }

func groupID(fp *Fingerprint, salt string) string {
	h := sha256.Sum256(append(append([]byte(nil), fp.Hash[:]...), []byte(salt)...))
	return hex.EncodeToString(h[:16])
}

// FindOrCreateGroup returns an existing similar group or creates a new one.
func (m *Matcher) FindOrCreateGroup(serviceID string, fp *Fingerprint, flowID string) *FlowGroup {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.nowFn()

	if gid, ok := m.exactIndex[fp.Hash]; ok {
		g := m.groups[gid]
		if g != nil {
			g.AddFlow(flowID, now)
			return g
		}
	}
	for _, g := range m.groups {
		if g.ServiceID != serviceID {
			continue
		}
		if fp.Similarity(g.Fingerprint) >= SimilarityThreshold {
			if _, ok := m.exactIndex[fp.Hash]; !ok {
				m.exactIndex[fp.Hash] = g.ID
			}
			g.AddFlow(flowID, now)
			return g
		}
	}
	id := groupID(fp, serviceID)
	g := NewFlowGroup(id, serviceID, fp, now)
	g.AddFlow(flowID, now)
	m.groups[id] = g
	m.exactIndex[fp.Hash] = id
	return g
}

func (m *Matcher) Get(id string) (*FlowGroup, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.groups[id]
	return g, ok
}

func (m *Matcher) All() []*FlowGroup {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*FlowGroup, 0, len(m.groups))
	for _, g := range m.groups {
		out = append(out, g)
	}
	return out
}

func (m *Matcher) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.groups)
}

// ForService returns all groups of a service.
func (m *Matcher) ForService(serviceID string) []*FlowGroup {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*FlowGroup
	for _, g := range m.groups {
		if g.ServiceID == serviceID {
			out = append(out, g)
		}
	}
	return out
}
