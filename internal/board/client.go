// Package board integrates with scoring boards (ForcAD, CTFd, FAUST).
package board

import (
	"net"
	"net/http"
	"time"

	"shieldgate/internal/status"
)

type ServiceInfo struct {
	ID       string
	Name     string
	Port     uint16
	Protocol string
}

type TeamInfo struct {
	ID   int
	Name string
	IP   net.IP
}

// BoardClient abstracts a specific scoring-board API.
type BoardClient interface {
	GetServices() ([]ServiceInfo, error)
	GetCheckerStatus(serviceID string) (status.CheckerStatus, error)
	GetTeams() ([]TeamInfo, error)
	GetOurIP() (net.IP, error)
	Poll() (map[string]status.CheckerStatus, error)
}

var _ BoardClient = (BoardClient)(nil)

// httpClient is shared by all adapters.
type httpClient struct {
	baseURL string
	token   string
	client  *http.Client
	timeout time.Duration
}

// CheckResult is a checker verdict with an optional human-readable failure
// reason (ForcAD exposes e.g. "Could not get flag", "Checker timed out").
type CheckResult struct {
	Status  status.CheckerStatus
	Message string
}

// DetailedPoller is implemented by boards that expose failure reasons.
type DetailedPoller interface {
	PollDetailed() (map[string]CheckResult, error)
}

// PollDetailedOf prefers DetailedPoller, degrading to plain Poll.
func PollDetailedOf(c BoardClient) (map[string]CheckResult, error) {
	if dp, ok := c.(DetailedPoller); ok {
		return dp.PollDetailed()
	}
	plain, err := c.Poll()
	if err != nil {
		return nil, err
	}
	out := make(map[string]CheckResult, len(plain))
	for id, st := range plain {
		out[id] = CheckResult{Status: st}
	}
	return out, nil
}
