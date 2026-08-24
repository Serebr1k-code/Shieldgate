package mirror

import (
	"errors"
	"log"
	"net"
	"sync"
	"syscall"
)

var ErrShortPacket = errors.New("mirror: packet too short")

// Engine mirrors banned packets to other teams' service IPs.
type Engine struct {
	mu      sync.RWMutex
	targets []net.IP

	raw     RawConn
	enabled bool
}

// RawConn abstracts the raw socket (mockable in tests).
type RawConn interface {
	WriteTo(b []byte, dst net.IP) error
	Close() error
}

type rawConn struct{ fd int }

// OpenRaw creates a raw IP socket (requires CAP_NET_RAW / root).
func OpenRaw() (RawConn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return &rawConn{fd: fd}, nil
}

func (r *rawConn) WriteTo(b []byte, dst net.IP) error {
	addr := &syscall.SockaddrInet4{Port: 0}
	copy(addr.Addr[:], dst.To4())
	return syscall.Sendto(r.fd, b, 0, addr)
}

func (r *rawConn) Close() error { return syscall.Close(r.fd) }

func New(enabled bool) *Engine { return &Engine{enabled: enabled} }

// SetEnabled toggles mirroring at runtime.
func (e *Engine) SetEnabled(v bool) { e.enabled = v }

// Connected reports whether a raw socket is attached.
func (e *Engine) Connected() bool { return e.raw != nil }

// SetRaw injects a raw connection (production or test).
func (e *Engine) SetRaw(c RawConn) { e.raw = c }

// Connect opens the real raw socket.
func (e *Engine) Connect() error {
	c, err := OpenRaw()
	if err != nil {
		return err
	}
	e.SetRaw(c)
	return nil
}

// SetTargets replaces the mirror destination list.
func (e *Engine) SetTargets(ips []net.IP) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.targets = append([]net.IP(nil), ips...)
}

func (e *Engine) Targets() []net.IP {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]net.IP, len(e.targets))
	copy(out, e.targets)
	return out
}

// Mirror rewrites and sends the packet to every target team.
// Caller must ensure policy allows mirroring (banned && !FlagSeen && !TempBanned).
func (e *Engine) Mirror(raw []byte) int {
	if !e.enabled || e.raw == nil {
		return 0
	}
	sent := 0
	for _, t := range e.Targets() {
		rewritten, err := RewritePacket(raw, t)
		if err != nil {
			log.Printf("mirror rewrite failed: %v", err)
			continue
		}
		if err := e.raw.WriteTo(rewritten, t); err != nil {
			log.Printf("mirror send to %s failed: %v", t, err)
			continue
		}
		sent++
	}
	return sent
}

func (e *Engine) Close() error {
	if e.raw != nil {
		return e.raw.Close()
	}
	return nil
}
