package api

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"shieldgate/internal/board"
	"shieldgate/internal/config"
	"shieldgate/internal/engine/classifier"
	"shieldgate/internal/state"
	"shieldgate/internal/status"
)

type mockBoard struct{}

func (mockBoard) GetServices() ([]board.ServiceInfo, error) {
	return []board.ServiceInfo{{ID: "svc1", Name: "test", Port: 5000, Protocol: "tcp"}}, nil
}
func (mockBoard) GetCheckerStatus(string) (status.CheckerStatus, error) {
	return status.CheckerGreen, nil
}
func (mockBoard) GetTeams() ([]board.TeamInfo, error) { return nil, nil }
func (mockBoard) GetOurIP() (net.IP, error)           { return net.ParseIP("10.0.0.9"), nil }
func (mockBoard) Poll() (map[string]status.CheckerStatus, error) {
	return map[string]status.CheckerStatus{"svc1": status.CheckerGreen}, nil
}

func newManagerForTest(t *testing.T) (*state.Manager, *state.Service) {
	t.Helper()
	cfg := config.Defaults()
	mgr, err := state.NewManager(cfg, mockBoard{})
	require.NoError(t, err)
	mgr.SyncServices([]board.ServiceInfo{{ID: "svc1", Name: "test", Port: 5000, Protocol: "tcp"}})
	svc, ok := mgr.Get("svc1")
	require.True(t, ok)
	return mgr, svc
}

func newServerForTest(t *testing.T) *Server {
	t.Helper()
	s, _ := newServerWithHub(t)
	return s
}

func newServerWithHub(t *testing.T) (*Server, *Hub) {
	t.Helper()
	mgr, svc := newManagerForTest(t)
	// Seed one allowed group so UI endpoints have data.
	fp := classifier.NewFingerprint([]byte("GET /status HTTP/1.1\r\nHost: x\r\n\r\n"))
	g := svc.Matcher.FindOrCreateGroup(svc.ID, fp, "flowA")
	g.SetStatus(classifier.GroupAllowed, time.Now())

	hub := NewHub()
	flows := classifier.NewManager(time.Minute, 4096)
	flows.Observe(6, net.ParseIP("10.0.0.66"), net.ParseIP("10.0.0.9"), 4444, 5000,
		"svc1", []byte("GET /status HTTP/1.1"), classifier.Inbound)
	return NewServer(ServerDeps{Manager: mgr, Flows: flows, Hub: hub}), hub
}
