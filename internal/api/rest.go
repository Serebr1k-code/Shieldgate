package api

import (
	"net/http"
	"strconv"
	"sync/atomic"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"shieldgate/internal/engine/classifier"
	"shieldgate/internal/state"
	"shieldgate/internal/storage"
)

// ServerDeps bundles what REST handlers need.
type ServerDeps struct {
	Manager *state.Manager
	Flows   *classifier.Manager
	Hub     *Hub
	Store   *storage.DB
	// Reconfigure applies new settings at runtime (board reconnect,
	// nftables rules, mirror targets). Optional.
	Reconfigure func(SettingsDTO) error
}

type Server struct {
	deps   ServerDeps
	router chi.Router
}

func NewServer(deps ServerDeps) *Server {
	s := &Server{deps: deps}
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/services", s.listServices)
		r.Patch("/services/{id}/groups/{groupID}", s.updateGroup)
		r.Get("/flows", s.listFlows)
		r.Get("/flows/{id}", s.getFlow)
		r.Post("/groups/{groupID}/status", s.setGroupStatus)
		r.Get("/settings", s.getSettings)
		r.Put("/settings", s.putSettings)
	})
	r.Get("/ws", deps.Hub.ServeWS)
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	s.router = r
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.router.ServeHTTP(w, r) }

var reqCounter atomic.Uint64

// --- handlers ---

func (s *Server) listServices(w http.ResponseWriter, r *http.Request) {
	type groupDTO struct {
		ID      string  `json:"id"`
		Status  string  `json:"status"`
		Weight  float64 `json:"weight"`
		Count   int     `json:"flows"`
		Checker *bool   `json:"is_checker,omitempty"`
	}
	type svcDTO struct {
		ID       string     `json:"id"`
		Name     string     `json:"name"`
		Port     uint16     `json:"port"`
		Protocol string     `json:"protocol"`
		Phase    string     `json:"phase"`
		Groups   []groupDTO `json:"groups"`
	}
	out := make([]svcDTO, 0)
	for _, svc := range s.deps.Manager.All() {
		dto := svcDTO{
			ID: svc.ID, Name: svc.Name, Port: svc.Port,
			Protocol: svc.Protocol, Phase: svc.Phase().String(),
			Groups: make([]groupDTO, 0),
		}
		for _, g := range svc.Matcher.ForService(svc.ID) {
			var checker *bool
			if g.IsChecker != nil {
				v := *g.IsChecker
				checker = &v
			}
			dto.Groups = append(dto.Groups, groupDTO{
				ID: g.ID, Status: g.GetStatus().String(),
				Weight: g.Weight, Count: g.Count, Checker: checker,
			})
		}
		out = append(out, dto)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) updateGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "groupID")
	svcID := chi.URLParam(r, "id")
	svc, ok := s.deps.Manager.Get(svcID)
	if !ok {
		httpError(w, http.StatusNotFound, "service not found")
		return
	}
	g, ok := svc.Matcher.Get(id)
	if !ok {
		httpError(w, http.StatusNotFound, "group not found")
		return
	}
	var body struct {
		IsChecker *bool `json:"is_checker,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.IsChecker != nil {
		g.IsChecker = body.IsChecker
		s.deps.Hub.Broadcast(Event{
			Type: "group.update", ServiceID: svcID,
			Message: "checker marking updated", At: timeNow(),
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) setGroupStatus(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "groupID")
	var body struct {
		Status string `json:"status"` // allowed | banned | candidate | temp_banned
	}
	if err := decodeJSON(r, &body); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	var target classifier.GroupStatus
	switch body.Status {
	case "allowed":
		target = classifier.GroupAllowed
	case "banned":
		target = classifier.GroupBanned
	case "temp_banned":
		target = classifier.GroupTempBanned
	case "candidate":
		target = classifier.GroupCandidate
	default:
		httpError(w, http.StatusBadRequest, "unknown status")
		return
	}
	found := false
	for _, svc := range s.deps.Manager.All() {
		if g, ok := svc.Matcher.Get(groupID); ok {
			g.SetStatus(target, timeNow())
			found = true
			s.deps.Hub.Broadcast(Event{
				Type: "group.update", ServiceID: svc.ID,
				Message: "status set to " + body.Status, At: timeNow(),
			})
			break
		}
	}
	if !found {
		httpError(w, http.StatusNotFound, "group not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listFlows(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	flows := s.deps.Flows.All()
	out := make([]map[string]any, 0, limit)
	for i, f := range flows {
		if i >= limit {
			break
		}
		out = append(out, flowDTO(f))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) getFlow(w http.ResponseWriter, r *http.Request) {
	f, ok := s.deps.Flows.Get(chi.URLParam(r, "id"))
	if !ok {
		httpError(w, http.StatusNotFound, "flow not found")
		return
	}
	dto := flowDTO(f)
	dto["payload_in"] = f.PayloadIn.Bytes()
	dto["payload_out"] = f.PayloadOut.Bytes()
	writeJSON(w, http.StatusOK, dto)
}

func flowDTO(f *classifier.Flow) map[string]any {
	return map[string]any{
		"id":        f.ID,
		"src":       f.SrcIP.String(),
		"dst":       f.DstIP.String(),
		"src_port":  f.SrcPort,
		"dst_port":  f.DstPort,
		"service":   f.ServiceID,
		"bytes_in":  f.BytesIn,
		"bytes_out": f.BytesOut,
		"status":    f.Status.String(),
		"group_id":  f.GroupID,
		"flag_seen": f.FlagSeen,
		"last_seen": f.LastSeen,
	}
}
