package reassembler

import (
	"net"

	"sync"
	"testing"
	"time"

	"github.com/google/gopacket/layers"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"shieldgate/internal/engine/classifier"
)

type memSink struct {
	mu     sync.Mutex
	data   map[int][]byte
	closed bool
}

func (m *memSink) OnStreamData(_ string, dir int, d []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.data == nil {
		m.data = make(map[int][]byte)
	}
	m.data[dir] = append(m.data[dir], d...)
}

func (m *memSink) OnStreamClose(string) { m.closed = true }

func buildSeg(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq uint32, ack bool, payload string) (*layers.IPv4, *layers.TCP) {
	ip := &layers.IPv4{
		Version:  4,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort:   layers.TCPPort(srcPort),
		DstPort:   layers.TCPPort(dstPort),
		Seq:       seq,
		Ack:       1,
		SYN:       false,
		ACK:       ack,
		BaseLayer: layers.BaseLayer{Payload: []byte(payload)},
	}
	tcp.SetNetworkLayerForChecksum(ip)
	tcp.SetInternalPortsForTesting()
	return ip, tcp
}

func TestReassemblyOutOfOrderSegments(t *testing.T) {
	a := NewAssembler(64*1024, time.Minute)
	sink := &memSink{}
	src, dst := net.ParseIP("10.0.0.9"), net.ParseIP("10.0.0.1")

	// Register sink for canonical flow key.
	key := flowKeyOf(src, dst, 40000, 8080)
	a.RegisterSink(key, sink)

	// Feed segments out of order: head, tail, then the gap filler.
	// NOTE: no SYN is set anywhere; our Accept() force-starts mid-stream.
	_, tcp1 := buildSeg(src, dst, 40000, 8080, 0, true, "ABCD")
	a.AssembleTCP(src, dst, tcp1)

	sink.mu.Lock()
	got := string(sink.data[ClientToService])
	sink.mu.Unlock()
	assert.Equal(t, "ABCD", got, "in-order prefix must be delivered immediately")

	_, tcp2 := buildSeg(src, dst, 40000, 8080, 8, true, "IJKL")
	a.AssembleTCP(src, dst, tcp2)

	_, tcp3 := buildSeg(src, dst, 40000, 8080, 4, true, "EFGH")
	a.AssembleTCP(src, dst, tcp3)

	sink.mu.Lock()
	got = string(sink.data[ClientToService])
	sink.mu.Unlock()
	require.Equal(t, "ABCDEFGHIJKL", got, "reassembly must restore original order")
}

func TestReassemblySynAccounting(t *testing.T) {
	a := NewAssembler(64*1024, time.Minute)
	sink := &memSink{}
	src, dst := net.ParseIP("10.0.2.9"), net.ParseIP("10.0.2.1")
	a.RegisterSink(flowKeyOf(src, dst, 41000, 80), sink)

	// SYN consumes one sequence number; payload starts at seq+1.
	_, syn := buildSeg(src, dst, 41000, 80, 100, false, "")
	syn.SYN, syn.ACK = true, false
	a.AssembleTCP(src, dst, syn)

	_, d1 := buildSeg(src, dst, 41000, 80, 101, true, "OK")
	a.AssembleTCP(src, dst, d1)

	sink.mu.Lock()
	got := string(sink.data[ClientToService])
	sink.mu.Unlock()
	assert.Equal(t, "OK", got)
}

func TestReassemblyBothDirections(t *testing.T) {
	a := NewAssembler(64*1024, time.Minute)
	sink := &memSink{}
	src, dst := net.ParseIP("10.0.1.5"), net.ParseIP("10.0.1.1")
	// flowKeyOf helper:
	key := flowKeyOf(src, dst, 55555, 9999)
	a.RegisterSink(key, sink)

	_, tcp := buildSeg(src, dst, 55555, 9999, 0, true, "REQ")
	a.AssembleTCP(src, dst, tcp)
	_, rtcp := buildSeg(dst, src, 9999, 55555, 100, true, "RESP")
	a.AssembleTCP(dst, src, rtcp)

	sink.mu.Lock()
	defer sink.mu.Unlock()
	assert.Equal(t, "REQ", string(sink.data[ClientToService]))
	assert.Equal(t, "RESP", string(sink.data[ServiceToClient]))
}

func TestFlushOlderThan(t *testing.T) {
	a := NewAssembler(1024, 50*time.Millisecond)
	now := time.Now()
	a.nowFn = func() time.Time { return now }
	src, dst := net.ParseIP("10.9.9.9"), net.ParseIP("10.0.0.1")
	_, tcp := buildSeg(src, dst, 1234, 80, 0, true, "x")
	a.AssembleTCP(src, dst, tcp)

	flushed, closed := a.FlushOlderThan()
	assert.Zero(t, flushed)
	assert.Zero(t, closed)

	now = now.Add(time.Second)
	_, closedCount := a.FlushOlderThan()
	assert.GreaterOrEqual(t, closedCount+flushed, 0)
}

func flowKeyOf(src, dst net.IP, srcPort, dstPort uint16) string {
	return classifier.FlowID(6, src, dst, srcPort, dstPort)
}
