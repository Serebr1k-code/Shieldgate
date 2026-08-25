// Package engine implements the NFQUEUE packet handler pipeline.
package engine

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	"shieldgate/internal/engine/classifier"
	"shieldgate/internal/engine/mirror"
	"shieldgate/internal/engine/nfqueue"
	"shieldgate/internal/engine/policy"
	"shieldgate/internal/state"
	"shieldgate/internal/storage"
)

// Engine is the central per-packet decision pipeline.
type Engine struct {
	mu     sync.RWMutex
	ourIP  net.IP
	mgr    *state.Manager
	flows  *classifier.Manager
	mirror *mirror.Engine
	store  *storage.DB

	onEvent func(state.Event)

	// debug counters
	calls      atomic.Uint64
	decodeFail atomic.Uint64
	unrelated  atomic.Uint64
	inbound    atomic.Uint64
	noService  atomic.Uint64
}

// DebugCounters exposes pipeline counters for the debug endpoint.
type DebugCounters struct {
	Calls      uint64 `json:"calls"`
	DecodeFail uint64 `json:"decode_fail"`
	Unrelated  uint64 `json:"unrelated"`
	Inbound    uint64 `json:"inbound"`
	NoService  uint64 `json:"no_service"`
}

func (e *Engine) Debug() DebugCounters {
	return DebugCounters{
		e.calls.Load(), e.decodeFail.Load(), e.unrelated.Load(),
		e.inbound.Load(), e.noService.Load(),
	}
}

func New(ourIP net.IP, mgr *state.Manager, flows *classifier.Manager,
	mir *mirror.Engine, store *storage.DB) *Engine {
	return &Engine{
		ourIP:  ourIP,
		mgr:    mgr,
		flows:  flows,
		mirror: mir,
		store:  store,
	}
}

func (e *Engine) OnEvent(f func(state.Event)) { e.onEvent = f }

// SetOurIP updates the local team IP once the board reports it.
func (e *Engine) SetOurIP(ip net.IP) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ourIP = ip
}

// Handle processes one intercepted packet and returns a verdict.
// Implements nfqueue.PacketHandler.
func (e *Engine) Handle(pkt *nfqueue.Packet) nfqueue.Verdict {
	e.calls.Add(1)
	srcIP, dstIP, srcPort, dstPort, proto, payload, ok := decode(pkt.Data)
	if !ok {
		e.decodeFail.Add(1)
		return nfqueue.Accept // not IP/TCP/UDP: let kernel handle it
	}

	e.mu.RLock()
	ourIP := e.ourIP
	e.mu.RUnlock()

	inbound := ourIP != nil && dstIP.Equal(ourIP)
	var servicePort uint16
	dir := classifier.Outbound
	if inbound {
		servicePort = dstPort
		dir = classifier.Inbound
	} else if ourIP != nil && srcIP.Equal(ourIP) {
		servicePort = srcPort
	} else {
		e.unrelated.Add(1)
		return nfqueue.Accept // unrelated traffic
	}
	e.inbound.Add(1)

	svc, ok := e.mgr.ServiceForPort(servicePort)
	if !ok {
		e.noService.Add(1)
		return nfqueue.Accept // no protected service on this port
	}

	// Track flow & payload.
	flow := e.flows.Observe(proto, srcIP, dstIP, srcPort, dstPort, svc.ID, payload, dir)

	// Feed request payload into grouping during Learning/Candidate phases.
	if dir == classifier.Inbound && len(payload) > 0 {
		fp := classifier.NewFingerprint(payload)
		g := svc.Matcher.FindOrCreateGroup(svc.ID, fp, flow.ID)
		flow.GroupID = g.ID

		// Flag detection on server-bound data.
		if !flow.FlagSeen && e.mgr.FlagDetector().Scan(payload) {
			flow.FlagSeen = true
			log.Printf("FLAG detected in flow %s from %s", shortID(flow.ID), srcIP)
			if e.store != nil {
				for _, f := range e.mgr.FlagDetector().Find(payload) {
					_ = e.store.LogFlag(time.Now(), svc.ID, srcIP.String(), f)
				}
			}
			e.emit("flag.detected", svc.ID, "flag in traffic from "+srcIP.String())
		}
	}

	// Policy decision.
	var decision policy.Decision

	switch svc.Phase() {
	case state.PhaseIdle, state.PhaseLearning:
		// During idle/learning we only record: everything passes except
		// flows where a flag was already seen.
		if flow.FlagSeen {
			decision = policy.Decision{Verdict: nfqueue.Drop, SendRST: true,
				Reason: "flag detected (learning)"}
		} else {
			decision = policy.Decision{Verdict: nfqueue.Accept, Reason: "learning"}
		}
	default:
		var group *classifier.FlowGroup
		if flow.GroupID != "" {
			group, _ = svc.Matcher.Get(flow.GroupID)
		}
		decision = policy.Evaluate(flow, group)
	}

	// Mirror banned packets (policy guarantees TempBanned/FlagSeen excluded).
	if decision.Mirror && len(pkt.Data) > 0 && dir == classifier.Inbound {
		e.mirror.Mirror(pkt.Data)
	}

	if e.store != nil && decision.Verdict != nfqueue.Accept {
		_ = e.store.LogDecision(storage.DecisionRow{
			TS: time.Now(), ServiceID: svc.ID, FlowID: flow.ID,
			Src: srcIP.String(), Dst: dstIP.String(),
			Verdict: decision.Verdict.String(), Reason: decision.Reason,
		})
	}
	return decision.Verdict
}

func (e *Engine) emit(typ, serviceID, msg string) {
	if e.onEvent == nil {
		return
	}
	e.onEvent(state.Event{Type: typ, ServiceID: serviceID, Message: msg, At: time.Now()})
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// decode extracts L3/L4 fields and payload from a raw IP packet.
func decode(data []byte) (srcIP, dstIP net.IP, srcPort, dstPort uint16, proto uint8, payload []byte, ok bool) {
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.DecodeOptions{NoCopy: true})
	ip4, is4 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	ip6, is6 := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	switch {
	case is4:
		srcIP, dstIP, proto = ip4.SrcIP, ip4.DstIP, uint8(ip4.Protocol)
	case is6:
		srcIP, dstIP, proto = ip6.SrcIP, ip6.DstIP, uint8(ip6.NextHeader)
	default:
		return nil, nil, 0, 0, 0, nil, false
	}
	if tcp, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		return srcIP, dstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort), proto, tcp.Payload, true
	}
	if udp, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		return srcIP, dstIP, uint16(udp.SrcPort), uint16(udp.DstPort), proto, udp.Payload, true
	}
	return nil, nil, 0, 0, 0, nil, false
}
