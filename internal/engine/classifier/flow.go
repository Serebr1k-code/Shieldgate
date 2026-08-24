package classifier

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sync"
	"time"
)

type FlowStatus int8

const (
	StatusUnknown FlowStatus = iota
	StatusAllowed
	StatusBanned
	StatusTempBanned
)

func (s FlowStatus) String() string {
	switch s {
	case StatusAllowed:
		return "allowed"
	case StatusBanned:
		return "banned"
	case StatusTempBanned:
		return "temp_banned"
	default:
		return "unknown"
	}
}

// Flow is a tracked connection (5-tuple + metadata + payload buffers).
type Flow struct {
	ID        string
	Protocol  uint8 // unix.IPPROTO_TCP etc.
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	ServiceID string

	CreatedAt time.Time
	LastSeen  time.Time
	ExpiresAt time.Time

	BytesIn    uint64
	BytesOut   uint64
	PayloadIn  *RingBuffer // server-bound payload
	PayloadOut *RingBuffer // client-bound payload (responses)

	Fingerprint *Fingerprint
	GroupID     string
	Status      FlowStatus
	IsChecker   *bool
	FlagSeen    bool
}

func FlowID(proto uint8, srcIP net.IP, dstIP net.IP, srcPort, dstPort uint16) string {
	// Canonical ordering: both directions of a connection map to one ID.
	a := endpointKey(srcIP, srcPort)
	b := endpointKey(dstIP, dstPort)
	if a > b {
		a, b = b, a
	}
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s", proto, a, b)))
	return hex.EncodeToString(h[:])
}

func endpointKey(ip net.IP, port uint16) string {
	return normalizeIP(ip) + "|" + fmt.Sprint(port)
}

func normalizeIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

// Direction of a packet relative to the protected service.
type Direction int8

const (
	Inbound  Direction = iota // towards service
	Outbound                  // from service to client
)

// Manager keeps active flows with TTL cleanup.
type Manager struct {
	mu         sync.RWMutex
	flows      map[string]*Flow
	ttl        time.Duration
	maxPayload int
	nowFn      func() time.Time
}

func NewManager(ttl time.Duration, maxPayload int) *Manager {
	return &Manager{
		flows:      make(map[string]*Flow),
		ttl:        ttl,
		maxPayload: maxPayload,
		nowFn:      time.Now,
	}
}

func (m *Manager) SetClock(f func() time.Time) { m.nowFn = f }

// Observe records a packet for a flow, creating it if needed.
// The 5-tuple is normalized so both directions map onto the same flow.
func (m *Manager) Observe(proto uint8, srcIP, dstIP net.IP, srcPort, dstPort uint16, serviceID string, payload []byte, dir Direction) *Flow {
	id := FlowID(proto, srcIP, dstIP, srcPort, dstPort)
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.nowFn()
	fl, ok := m.flows[id]
	if !ok {
		fl = &Flow{
			ID:         id,
			Protocol:   proto,
			SrcIP:      append(net.IP(nil), srcIP...),
			DstIP:      append(net.IP(nil), dstIP...),
			SrcPort:    srcPort,
			DstPort:    dstPort,
			ServiceID:  serviceID,
			CreatedAt:  now,
			PayloadIn:  NewRingBuffer(m.maxPayload),
			PayloadOut: NewRingBuffer(m.maxPayload),
		}
		m.flows[id] = fl
	}
	fl.LastSeen = now
	fl.ExpiresAt = now.Add(m.ttl)
	if dir == Inbound {
		fl.BytesIn += uint64(len(payload))
		fl.PayloadIn.Write(payload)
	} else {
		fl.BytesOut += uint64(len(payload))
		fl.PayloadOut.Write(payload)
	}
	return fl
}

func (m *Manager) Get(id string) (*Flow, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	f, ok := m.flows[id]
	return f, ok
}

func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.flows)
}

// Cleanup removes expired flows and returns them.
func (m *Manager) Cleanup() []*Flow {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.nowFn()
	var expired []*Flow
	for id, f := range m.flows {
		if now.After(f.ExpiresAt) {
			expired = append(expired, f)
			delete(m.flows, id)
		}
	}
	return expired
}

func (m *Manager) All() []*Flow {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Flow, 0, len(m.flows))
	for _, f := range m.flows {
		out = append(out, f)
	}
	return out
}
