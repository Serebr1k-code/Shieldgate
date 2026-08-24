// Package ctfd implements the CTFd (AD plugin) scoring board adapter.
package ctfd

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"shieldgate/internal/board"
	"shieldgate/internal/status"
)

type Adapter struct {
	h       http.Client
	baseURL string
	token   string
}

func New(baseURL, token string) *Adapter {
	return &Adapter{
		h:       http.Client{Timeout: 10 * time.Second},
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
	}
}

func (a *Adapter) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, a.baseURL+path, nil)
	if err != nil {
		return err
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Token "+a.token)
	}
	resp, err := a.h.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ctfd %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type apiEnvelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
}

type serviceDTO struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func (a *Adapter) GetServices() ([]board.ServiceInfo, error) {
	var env apiEnvelope
	if err := a.get("/api/v1/services", &env); err != nil {
		return nil, err
	}
	var dtos []serviceDTO
	if err := json.Unmarshal(env.Data, &dtos); err != nil {
		return nil, err
	}
	out := make([]board.ServiceInfo, 0, len(dtos))
	for _, d := range dtos {
		p := d.Protocol
		if p == "" {
			p = "tcp"
		}
		out = append(out, board.ServiceInfo{
			ID:       "ctfd_" + strings.ToLower(strings.ReplaceAll(d.Name, " ", "_")),
			Name:     d.Name,
			Port:     uint16(d.Port),
			Protocol: p,
		})
	}
	return out, nil
}

type scoreboardEntry struct {
	TeamID   int               `json:"team_id"`
	Statuses map[string]string `json:"service_statuses"`
}

// GetCheckerStatus reads per-service statuses from the AD plugin scoreboard.
func (a *Adapter) GetCheckerStatus(serviceID string) (status.CheckerStatus, error) {
	var env apiEnvelope
	if err := a.get("/api/v1/scoreboard", &env); err != nil {
		return status.CheckerUnknown, err
	}
	var entries []scoreboardEntry
	if err := json.Unmarshal(env.Data, &entries); err != nil {
		return status.CheckerUnknown, err
	}
	svcName := strings.TrimPrefix(serviceID, "ctfd_")
	for _, e := range entries {
		if st, ok := e.Statuses[svcName]; ok {
			return status.FromBoardStatus(st), nil
		}
	}
	return status.CheckerUnknown, nil
}

func (a *Adapter) GetTeams() ([]board.TeamInfo, error) {
	var env apiEnvelope
	if err := a.get("/api/v1/teams", &env); err != nil {
		return nil, err
	}
	var dtos []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
		IP   string `json:"ip"`
	}
	if err := json.Unmarshal(env.Data, &dtos); err != nil {
		return nil, err
	}
	out := make([]board.TeamInfo, 0, len(dtos))
	for _, d := range dtos {
		ip := net.ParseIP(d.IP)
		if ip != nil {
			out = append(out, board.TeamInfo{ID: d.ID, Name: d.Name, IP: ip})
		}
	}
	return out, nil
}

// GetOurIP resolves our team IP from the team profile endpoint.
func (a *Adapter) GetOurIP() (net.IP, error) {
	var env apiEnvelope
	if err := a.get("/api/v1/team/me", &env); err != nil {
		return nil, err
	}
	var dto struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(env.Data, &dto); err != nil {
		return nil, err
	}
	ip := net.ParseIP(dto.IP)
	if ip == nil {
		return nil, fmt.Errorf("ctfd: bad self ip %q", dto.IP)
	}
	return ip, nil
}

func (a *Adapter) Poll() (map[string]status.CheckerStatus, error) {
	services, err := a.GetServices()
	if err != nil {
		return nil, err
	}
	out := make(map[string]status.CheckerStatus)
	for _, s := range services {
		st, err := a.GetCheckerStatus(s.ID)
		if err != nil {
			continue
		}
		out[s.ID] = st
	}
	return out, nil
}
