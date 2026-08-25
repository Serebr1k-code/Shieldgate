package forcad

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"shieldgate/internal/board"
	"shieldgate/internal/status"
)

// SocketAdapter reads ForcAD data through the socket.io endpoint used by the
// web scoreboard (/game_events namespace). It works even when the REST API is
// not proxied publicly.
type SocketAdapter struct {
	h        http.Client
	baseURL  string
	ourIPStr string
	ports    map[string]uint16 // task name -> port (scoreboard does not expose ports)

	mu       sync.Mutex
	snapshot *snapshot
}

type snapshot struct {
	Tasks []struct {
		ID   int    `json:"id"`
		Name string `json:"name"`
	} `json:"tasks"`
	Teams []struct {
		ID     int    `json:"id"`
		Name   string `json:"name"`
		IP     string `json:"ip"`
		Active bool   `json:"active"`
	} `json:"teams"`
	State struct {
		Round     int `json:"round"`
		TeamTasks []struct {
			TaskID  int     `json:"task_id"`
			TeamID  int     `json:"team_id"`
			Status  int     `json:"status"` // 101 UP 102 CORRUPT 103 MUMBLE 104 DOWN 110 CHECKFAILED
			Score   float64 `json:"score"`
			Message string  `json:"message"`
		} `json:"team_tasks"`
	} `json:"state"`
}

func NewSocket(baseURL string, ports map[string]uint16) *SocketAdapter {
	return &SocketAdapter{
		h:       http.Client{Timeout: 20 * time.Second},
		baseURL: strings.TrimRight(baseURL, "/"),
		ports:   ports,
	}
}

// refresh performs an engine.io v4 polling handshake, joins the
// /game_events namespace and captures init_scoreboard.
func (a *SocketAdapter) refresh() error {
	const sep = "\x1e"
	base := a.baseURL + "/socket.io/"

	resp, err := a.h.Get(base + "?EIO=4&transport=polling")
	if err != nil {
		return err
	}
	handshake, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var hs struct {
		SID string `json:"sid"`
	}
	body := strings.TrimPrefix(string(handshake), "0")
	if err := json.Unmarshal([]byte(body), &hs); err != nil || hs.SID == "" {
		return fmt.Errorf("forcad socket handshake failed")
	}

	join := "40/game_events,"
	req, _ := http.NewRequest(http.MethodPost,
		base+"?EIO=4&transport=polling&sid="+hs.SID, strings.NewReader(join))
	req.Header.Set("Content-Type", "text/plain;charset=UTF-8")
	resp, err = a.h.Do(req)
	if err != nil {
		return err
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("forcad socket join: status %d", resp.StatusCode)
	}

	// Poll until init_scoreboard arrives (bounded attempts).
	for attempt := 0; attempt < 5; attempt++ {
		resp, err = a.h.Get(base + "?EIO=4&transport=polling&sid=" + hs.SID)
		if err != nil {
			return err
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		for _, pkt := range strings.Split(string(raw), sep) {
			marker := `42/game_events,["init_scoreboard",`
			if !strings.HasPrefix(pkt, marker) {
				continue
			}
			payload := pkt[len(marker):]
			payload = strings.TrimSuffix(payload, "]") // closing bracket of event array

			var env struct {
				Data snapshot `json:"data"`
			}
			if err := json.Unmarshal([]byte(payload), &env); err != nil {
				return fmt.Errorf("forcad snapshot decode: %w", err)
			}
			a.mu.Lock()
			a.snapshot = &env.Data
			a.mu.Unlock()

			// Politely leave the namespace.
			bye, _ := http.NewRequest(http.MethodPost,
				base+"?EIO=4&transport=polling&sid="+hs.SID, strings.NewReader("41/game_events,"))
			a.h.Do(bye) //nolint:errcheck — best effort
			return nil
		}
	}
	return fmt.Errorf("forcad: no init_scoreboard received")
}

func (a *SocketAdapter) getSnapshot() (*snapshot, error) {
	a.mu.Lock()
	s := a.snapshot
	a.mu.Unlock()
	if s == nil {
		if err := a.refresh(); err != nil {
			return nil, err
		}
		a.mu.Lock()
		s = a.snapshot
		a.mu.Unlock()
	}
	if s == nil {
		return nil, fmt.Errorf("forcad: no data")
	}
	return s, nil
}

func (a *SocketAdapter) GetServices() ([]board.ServiceInfo, error) {
	s, err := a.getSnapshot()
	if err != nil {
		return nil, err
	}
	out := make([]board.ServiceInfo, 0, len(s.Tasks))
	for _, t := range s.Tasks {
		port := a.ports[strings.ToLower(t.Name)]
		out = append(out, board.ServiceInfo{
			ID:       "forcad_" + t.Name,
			Name:     t.Name,
			Port:     port,
			Protocol: "tcp",
		})
	}
	return out, nil
}

func (a *SocketAdapter) GetCheckerStatus(serviceID string) (status.CheckerStatus, error) {
	s, err := a.getSnapshot()
	if err != nil {
		return status.CheckerUnknown, err
	}
	taskID, ok := a.taskID(s, serviceID)
	if !ok {
		return status.CheckerUnknown, fmt.Errorf("forcad: unknown task %s", serviceID)
	}
	teamID, ok := a.ourTeamID(s)
	if !ok {
		return status.CheckerUnknown, fmt.Errorf("forcad: our team not found by ip %s", a.ourIPStr)
	}
	for _, tt := range s.State.TeamTasks {
		if tt.TaskID == taskID && tt.TeamID == teamID {
			return codeToStatus(tt.Status), nil
		}
	}
	return status.CheckerUnknown, nil
}

func (a *SocketAdapter) taskID(s *snapshot, serviceID string) (int, bool) {
	name := strings.TrimPrefix(serviceID, "forcad_")
	for _, t := range s.Tasks {
		if t.Name == name {
			return t.ID, true
		}
	}
	return 0, false
}

func (a *SocketAdapter) ourTeamID(s *snapshot) (int, bool) {
	if a.ourIPStr == "" {
		return 0, false
	}
	for _, t := range s.Teams {
		if t.IP == a.ourIPStr {
			return t.ID, true
		}
	}
	return 0, false
}

// codeToStatus maps ForcAD checker codes onto ShieldGate statuses.
func codeToStatus(code int) status.CheckerStatus {
	switch code {
	case 101:
		return status.CheckerGreen
	case 102, 103, 104, 110:
		return status.CheckerRed
	default:
		return status.CheckerUnknown
	}
}

func (a *SocketAdapter) GetTeams() ([]board.TeamInfo, error) {
	s, err := a.getSnapshot()
	if err != nil {
		return nil, err
	}
	out := make([]board.TeamInfo, 0, len(s.Teams))
	for _, t := range s.Teams {
		ip := parseIP(t.IP)
		if ip != nil && !t.Active {
			continue // don't mirror to inactive teams
		}
		if ip != nil {
			out = append(out, board.TeamInfo{ID: t.ID, Name: t.Name, IP: ip})
		}
	}
	return out, nil
}

func (a *SocketAdapter) GetOurIP() (ip net.IP, err error) {
	if a.ourIPStr == "" {
		return nil, fmt.Errorf("forcad: our_ip not configured")
	}
	ip = parseIP(a.ourIPStr)
	if ip == nil {
		return nil, fmt.Errorf("forcad: bad our_ip %q", a.ourIPStr)
	}
	return ip, nil
}

// Poll refreshes the snapshot and returns statuses for every known task.
func (a *SocketAdapter) Poll() (map[string]status.CheckerStatus, error) {
	if err := a.refresh(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	s := a.snapshot
	a.mu.Unlock()
	teamID, haveTeam := a.ourTeamID(s)
	statusByTask := map[int]int{}
	for _, tt := range s.State.TeamTasks {
		if !haveTeam || tt.TeamID == teamID {
			statusByTask[tt.TaskID] = tt.Status
		}
	}
	out := make(map[string]status.CheckerStatus)
	for _, t := range s.Tasks {
		out["forcad_"+t.Name] = codeToStatus(statusByTask[t.ID])
	}
	return out, nil
}

func parseIP(s string) net.IP {
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	return nil
}

// SetOurIP configures the local team IP used to locate our team in the
// scoreboard listing.
func (a *SocketAdapter) SetOurIP(ipStr string) { a.ourIPStr = ipStr }

// PollDetailed returns statuses enriched with ForcAD failure messages.
func (a *SocketAdapter) PollDetailed() (map[string]board.CheckResult, error) {
	if err := a.refresh(); err != nil {
		return nil, err
	}
	a.mu.Lock()
	s := a.snapshot
	a.mu.Unlock()

	teamID, haveTeam := a.ourTeamID(s)
	msgByTask := map[int]string{}
	statusByTask := map[int]int{}
	for _, tt := range s.State.TeamTasks {
		if !haveTeam || tt.TeamID == teamID {
			statusByTask[tt.TaskID] = tt.Status
			msgByTask[tt.TaskID] = tt.Message
		}
	}
	out := make(map[string]board.CheckResult)
	for _, t := range s.Tasks {
		out["forcad_"+t.Name] = board.CheckResult{
			Status:  codeToStatus(statusByTask[t.ID]),
			Message: msgByTask[t.ID],
		}
	}
	return out, nil
}

var _ board.DetailedPoller = (*SocketAdapter)(nil)
