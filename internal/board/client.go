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
