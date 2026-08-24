package mirror

import (
	"encoding/binary"

	"github.com/google/gopacket"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/google/gopacket/layers"
)

// buildRawTCPPacket constructs a valid IPv4+TCP packet with correct
// checksums for the given src/dst.
func buildRawTCPPacket(t *testing.T, src, dst net.IP, srcPort, dstPort uint16, payload string) []byte {
	t.Helper()
	ip := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		SrcIP:    src,
		DstIP:    dst,
		Protocol: layers.IPProtocolTCP,
	}
	tcp := &layers.TCP{
		SrcPort:   layers.TCPPort(srcPort),
		DstPort:   layers.TCPPort(dstPort),
		Seq:       1,
		Ack:       1,
		ACK:       true,
		PSH:       true,
		BaseLayer: layers.BaseLayer{Payload: []byte(payload)},
	}
	tcp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ip, tcp, gopacket.Payload(payload)); err != nil {
		t.Fatal(err)
	}
	out := append([]byte(nil), buf.Bytes()...)
	return out
}

type captureConn struct {
	mu     sync.Mutex
	sent   map[string][]byte
	closed bool
}

func (c *captureConn) WriteTo(b []byte, dst net.IP) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sent == nil {
		c.sent = make(map[string][]byte)
	}
	c.sent[dst.String()] = append([]byte(nil), b...)
	return nil
}
func (c *captureConn) Close() error { c.closed = true; return nil }

func TestRewriteChangesDstAndChecksums(t *testing.T) {
	src := net.ParseIP("10.10.66.6")
	dst := net.ParseIP("10.10.9.9")
	target := net.ParseIP("10.10.77.7")
	raw := buildRawTCPPacket(t, src, dst, 44444, 5000, "EXPLOIT")

	out, err := RewritePacket(raw, target)
	require.NoError(t, err)

	// Destination IP replaced.
	assert.Equal(t, target.String(), net.IP(out[16:20]).String())
	assert.Equal(t, src.String(), net.IP(out[12:16]).String(), "source must stay untouched")

	// IP checksum must be valid: recompute from scratch and compare.
	storedIP := readBE16(out[10:])
	binary.BigEndian.PutUint16(out[10:], 0)
	assert.Equal(t, storedIP, checksum(out[:20]), "ip checksum")

	// TCP checksum must be valid.
	ipHdrLen := int(out[0]&0x0F) * 4
	tcpBytes := out[ipHdrLen:]
	storedTCP := readBE16(tcpBytes[16:])
	binary.BigEndian.PutUint16(tcpBytes[16:], 0)
	pseudo := buildPseudoV4(src, target, 6, len(tcpBytes))
	assert.Equal(t, storedTCP, checksum(append(pseudo, tcpBytes...)), "tcp checksum")
}

func TestMirrorSendsToAllTargetsExceptTempBannedRules(t *testing.T) {
	e := New(true)
	conn := &captureConn{}
	e.SetRaw(conn)
	e.SetTargets([]net.IP{
		net.ParseIP("10.60.1.1"),
		net.ParseIP("10.60.2.2"),
		net.ParseIP("10.60.3.3"),
	})

	raw := buildRawTCPPacket(t,
		net.ParseIP("10.60.9.9"), net.ParseIP("10.60.9.9"), 1234, 5000, "x")
	n := e.Mirror(raw)
	assert.Equal(t, 3, n)
	assert.Len(t, conn.sent, 3)
	for ip := range conn.sent {
		assert.NotEqual(t, "10.60.9.9", ip)
	}
}

func TestMirrorDisabledOrNoRawIsNoop(t *testing.T) {
	disabled := New(false)
	disabled.SetTargets([]net.IP{net.ParseIP("10.0.0.1")})
	assert.Zero(t, disabled.Mirror(make([]byte, 40)))

	noSocket := New(true)
	assert.Zero(t, noSocket.Mirror(make([]byte, 40)))
}

func TestRewriteShortPacketErrors(t *testing.T) {
	_, err := RewritePacket([]byte{0x45}, net.ParseIP("1.2.3.4"))
	assert.ErrorIs(t, err, ErrShortPacket)
}

func TestChecksumKnownVector(t *testing.T) {
	// RFC 1071 example-style sanity: checksum of zero data is 0xFFFF.
	assert.EqualValues(t, 0xFFFF, checksum([]byte{0, 0}))
}

func readBE16(b []byte) uint16 { return binary.BigEndian.Uint16(b) }
