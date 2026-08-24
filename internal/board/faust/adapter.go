// Package faust implements the FAUST CTF gameserver adapter.
package faust

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
}

func New(baseURL string) *Adapter {
	return &Adapter{
		h:       http.Client{Timeout: 10 * time.Second},
		baseURL: strings.TrimRight(baseURL, "/"),
	}
}

func (a *Adapter) get(path string, out any) error {
	resp, err := a.h.Get(a.baseURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("faust %s: status %d", path, resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type scoreboardDTO struct {
	Teams []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
		IP   string `json:"ip"`
	} `json:"teams"`
	Services []serviceDTO `json:"services"`
}

type serviceDTO struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

func (a *Adapter) GetServices() ([]board.ServiceInfo, error) {
	var dto scoreboardDTO
	if err := a.get("/scoreboard", &dto); err != nil {
		return nil, err
	}
	out := make([]board.ServiceInfo, 0, len(dto.Services))
	for _, d := range dto.Services {
		p := d.Protocol
		if p == "" {
			p = "tcp"
		}
		out = append(out, board.ServiceInfo{
			ID:       "faust_" + strings.ToLower(strings.ReplaceAll(d.Name, " ", "_")),
			Name:     d.Name,
			Port:     uint16(d.Port),
			Protocol: p,
		})
	}
	return out, nil
}

func (a *Adapter) GetCheckerStatus(serviceID string) (status.CheckerStatus, error) {
	var dto struct {
		Services map[string]string `json:"services"`
	}
	if err := a.get("/service_status", &dto); err != nil {
		return status.CheckerUnknown, err
	}
	name := strings.TrimPrefix(serviceID, "faust_")
	for n, st := range dto.Services {
		if strings.EqualFold(n, name) || "faust_"+strings.ToLower(n) == serviceID {
			return status.FromBoardStatus(st), nil
		}
	}
	return status.CheckerUnknown, nil
}

func (a *Adapter) GetTeams() ([]board.TeamInfo, error) {
	var dto scoreboardDTO
	if err := a.get("/scoreboard", &dto); err != nil {
		return nil, err
	}
	out := make([]board.TeamInfo, 0, len(dto.Teams))
	for _, t := range dto.Teams {
		ip := net.ParseIP(t.IP)
		if ip != nil {
			out = append(out, board.TeamInfo{ID: t.ID, Name: t.Name, IP: ip})
		}
	}
	return out, nil
}

func (a *Adapter) GetOurIP() (net.IP, error) {
	var dto struct {
		TeamIP string `json:"team_ip"`
	}
	if err := a.get("/whoami", &dto); err != nil {
		return nil, err
	}
	ip := net.ParseIP(dto.TeamIP)
	if ip == nil {
		return nil, fmt.Errorf("faust: bad self ip %q", dto.TeamIP)
	}
	return ip, nil
}

func (a *Adapter) Poll() (map[string]status.CheckerStatus, error) {
	services, err := a.GetServices()
	if err != nil {
		return nil, err
	}
	var dto struct {
		Services map[string]string `json:"services"`
	}
	if err := a.get("/service_status", &dto); err != nil {
		return nil, err
	}
	out := make(map[string]status.CheckerStatus)
	for _, s := range services {
		name := strings.TrimPrefix(s.ID, "faust_")
		for n, st := range dto.Services {
			if strings.EqualFold(n, name) {
				out[s.ID] = status.FromBoardStatus(st)
			}
		}
	}
	return out, nil
}

var _ board.BoardClient = (*Adapter)(nil)
