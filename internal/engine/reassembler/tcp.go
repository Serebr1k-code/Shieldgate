// Package reassembler reorders out-of-order TCP segments into ordered
// byte streams using gopacket/reassembly.
package reassembler

import (
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/reassembly"

	"shieldgate/internal/engine/classifier"
)

// Directions relative to the protected service.
const (
	ClientToService = 0
	ServiceToClient = 1
)

// StreamSink receives reassembled, ordered stream bytes per direction.
type StreamSink interface {
	OnStreamData(flowKey string, dir int, data []byte)
	OnStreamClose(flowKey string)
}

type nopSink struct{}

func (nopSink) OnStreamData(string, int, []byte) {}
func (nopSink) OnStreamClose(string)             {}

type stream struct {
	key     string
	sink    StreamSink
	maxKeep int
}

func (s *stream) Accept(_ *layers.TCP, _ gopacket.CaptureInfo, _ reassembly.TCPFlowDirection, _ reassembly.Sequence, start *bool, _ reassembly.AssemblerContext) bool {
	// Accept streams even without a SYN (mid-capture flows).
	if start != nil {
		*start = true
	}
	return true
}

func (s *stream) ReassembledSG(sg reassembly.ScatterGather, _ reassembly.AssemblerContext) {
	length, _ := sg.Lengths()
	if length <= 0 {
		return
	}
	dir, _, _, _ := sg.Info()
	d := ClientToService
	if dir == reassembly.TCPDirServerToClient {
		d = ServiceToClient
	}
	data := sg.Fetch(length)
	if len(data) > s.maxKeep {
		data = data[len(data)-s.maxKeep:]
	}
	s.sink.OnStreamData(s.key, d, data)
	// All fetched bytes are consumed; leaving toKeep unset (-1)
	// discards them instead of re-saving.
}

func (s *stream) ReassemblyComplete(_ reassembly.AssemblerContext) bool {
	s.sink.OnStreamClose(s.key)
	return true
}

type factory struct {
	mu      sync.Mutex
	sinks   map[string]StreamSink
	maxKeep int
}

func (f *factory) New(netFlow, transport gopacket.Flow, _ *layers.TCP, _ reassembly.AssemblerContext) reassembly.Stream {
	sp := bePort(transport.Src().Raw())
	dp := bePort(transport.Dst().Raw())
	key := classifier.FlowID(6,
		netFlow.Src().Raw(), netFlow.Dst().Raw(), sp, dp)
	f.mu.Lock()
	defer f.mu.Unlock()
	var sink StreamSink = nopSink{}
	if s, ok := f.sinks[key]; ok {
		sink = s
	}
	return &stream{key: key, sink: sink, maxKeep: f.maxKeep}
}

type ctxInfo gopacket.CaptureInfo

func (c ctxInfo) GetCaptureInfo() gopacket.CaptureInfo { return gopacket.CaptureInfo(c) }

// Assembler wraps the gopacket TCP assembler.
type Assembler struct {
	assembler *reassembly.Assembler
	factory   *factory
	streams   map[string]time.Time
	mu        sync.Mutex
	ttl       time.Duration
	nowFn     func() time.Time
}

func NewAssembler(maxKeep int, ttl time.Duration) *Assembler {
	f := &factory{sinks: make(map[string]StreamSink), maxKeep: maxKeep}
	return &Assembler{
		assembler: reassembly.NewAssembler(reassembly.NewStreamPool(f)),
		factory:   f,
		streams:   make(map[string]time.Time),
		ttl:       ttl,
		nowFn:     time.Now,
	}
}

// RegisterSink routes reassembled data for a flow key to a sink.
// Must be called before the first segment of the flow arrives.
func (a *Assembler) RegisterSink(flowKey string, s StreamSink) {
	a.factory.mu.Lock()
	defer a.factory.mu.Unlock()
	a.factory.sinks[flowKey] = s
}

// AssembleTCP feeds one TCP segment into the reassembler.
func (a *Assembler) AssembleTCP(srcIP, dstIP net.IP, tcp *layers.TCP) {
	now := a.nowFn()
	et := layers.EndpointIPv4
	if srcIP.To4() == nil {
		et = layers.EndpointIPv6
	}
	netFlow := gopacket.NewFlow(et, srcIP.To16(), dstIP.To16())
	a.assembler.AssembleWithContext(netFlow, tcp, ctxInfo(gopacket.CaptureInfo{Timestamp: now}))
	a.mu.Lock()
	defer a.mu.Unlock()
	key := classifier.FlowID(6,
		srcIP, dstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort))
	a.streams[key] = now
}

// FlushOlderThan closes idle streams; returns number flushed/closed.
func (a *Assembler) FlushOlderThan() (flushed, closed int) {
	cutoff := a.nowFn().Add(-a.ttl)
	a.mu.Lock()
	a.streams = nil
	a.mu.Unlock()
	return a.assembler.FlushCloseOlderThan(cutoff)
}

func bePort(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
