// Package forcad implements the ForcAD scoring board adapter.
package forcad

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
		return fmt.Errorf("forcad %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type serviceDTO struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func (a *Adapter) GetServices() ([]board.ServiceInfo, error) {
	var dtos []serviceDTO
	if err := a.get("/api/services", &dtos); err != nil {
		return nil, err
	}
	out := make([]board.ServiceInfo, 0, len(dtos))
	for _, d := range dtos {
		p := d.Protocol
		if p == "" {
			p = "tcp"
		}
		out = append(out, board.ServiceInfo{
			ID:       "forcad_" + strings.ToLower(strings.ReplaceAll(d.Name, " ", "_")),
			Name:     d.Name,
			Port:     uint16(d.Port),
			Protocol: p,
		})
	}
	return out, nil
}

func (a *Adapter) GetCheckerStatus(serviceID string) (status.CheckerStatus, error) {
	name := strings.TrimPrefix(serviceID, "forcad_")
	var dto struct {
		Status string `json:"status"`
	}
	if err := a.get("/api/checker/"+name, &dto); err != nil {
		return status.CheckerUnknown, err
	}
	return status.FromBoardStatus(dto.Status), nil
}

type teamDTO struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	IP   string `json:"ip"`
}

func (a *Adapter) GetTeams() ([]board.TeamInfo, error) {
	var dtos []teamDTO
	if err := a.get("/api/teams", &dtos); err != nil {
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

func (a *Adapter) GetOurIP() (net.IP, error) {
	var dto teamDTO
	if err := a.get("/api/team/self", &dto); err != nil {
		return nil, err
	}
	ip := net.ParseIP(dto.IP)
	if ip == nil {
		return nil, fmt.Errorf("forcad: bad self ip %q", dto.IP)
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
			continue // keep last known status on errors
		}
		out[s.ID] = st
	}
	return out, nil
}
