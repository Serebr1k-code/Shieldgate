package forcad

import (
	"net"

	"shieldgate/internal/board"
	"shieldgate/internal/status"
)

// PortOverride decorates a BoardClient, forcing configured ports onto
// discovered services (scoreboards often omit port numbers).
type PortOverride struct {
	Client board.BoardClient
	Ports  map[string]uint16
}

func (p *PortOverride) GetServices() ([]board.ServiceInfo, error) {
	svcs, err := p.Client.GetServices()
	if err != nil {
		return nil, err
	}
	for i := range svcs {
		name := lower(svcs[i].Name)
		if p.Ports[name] > 0 {
			svcs[i].Port = p.Ports[name]
		} else if p.Ports[svcs[i].ID] > 0 {
			svcs[i].Port = p.Ports[svcs[i].ID]
		}
	}
	return svcs, nil
}

func lower(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

func (p *PortOverride) GetCheckerStatus(id string) (status.CheckerStatus, error) {
	return p.Client.GetCheckerStatus(id)
}
func (p *PortOverride) GetTeams() ([]board.TeamInfo, error) { return p.Client.GetTeams() }
func (p *PortOverride) GetOurIP() (net.IP, error)           { return p.Client.GetOurIP() }
func (p *PortOverride) Poll() (map[string]status.CheckerStatus, error) {
	return p.Client.Poll()
}
