//go:build integration

// Integration tests require root: they install real nftables rules and
// bind kernel NFQUEUEs. Run with:
//
//	sudo go test ./internal/engine/nfqueue -tags integration -v
package nfqueue

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type countingHandler struct {
	ch chan Verdict
	v  Verdict
}

func (h *countingHandler) Handle(p *Packet) Verdict {
	h.ch <- h.v
	return h.v
}

func TestNFQUEUEIntegration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	h := &countingHandler{ch: make(chan Verdict, 16), v: Drop}
	q, err := Open(19999, 1024, 32, h)
	if err != nil {
		t.Fatalf("open queue: %v", err)
	}
	defer q.Close()

	// Rule manager must point at the SAME queue number we opened above:
	// port index 0 gets queueStart + 0.
	rm := NewRuleManager(19999)
	if err := rm.InstallPorts([]uint16{39997}); err != nil {
		t.Fatalf("install rules: %v", err)
	}
	defer rm.Teardown()

	time.Sleep(500 * time.Millisecond) // let nft rules propagate

	// Send a SYN to the queued port; it must be dropped (no reply).
	// Nothing listens on this port, but with DROP the SYN never reaches
	// the stack at all, so we must see RST-refused only via verdict path.
	conn, err := net.DialTimeout("tcp", "127.0.0.1:39997", time.Second)
	if err == nil {
		conn.Close()
		t.Fatal("connection should have been dropped by NFQUEUE DROP verdict")
	}

	select {
	case v := <-h.ch:
		if v != Drop {
			t.Fatalf("expected DROP verdict, got %v", v)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no packet reached userspace handler")
	}
}

var _ = gopacket.NewPacket
var _ = layers.LayerTypeIPv4
