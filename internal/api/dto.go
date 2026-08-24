package api

import (
	"encoding/json"
	"net/http"
	"time"

	"shieldgate/internal/state"
)

func timeNow() time.Time { return time.Now() }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func decodeJSON(r *http.Request, out any) error {
	dec := json.NewDecoder(r.Body)
	defer r.Body.Close()
	return dec.Decode(out)
}

// SettingsDTO is the UI-facing application configuration.
type SettingsDTO struct {
	Board struct {
		Type      string            `json:"type"` // forcad | ctfd | faust
		URL       string            `json:"url"`
		Token     string            `json:"token"`
		OurIP     string            `json:"our_ip"`
		TaskPorts map[string]uint16 `json:"task_ports"`
	} `json:"board"`
	RoundDurationMinutes int     `json:"round_duration_minutes"`
	FlagRegex            string  `json:"flag_regex"`
	BanFraction          float64 `json:"ban_fraction"`
	MirrorEnabled        bool    `json:"mirror_enabled"`
}

const settingsKey = "app_config"

// getSettings returns the persisted configuration (or empty defaults).
func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	if s.deps.Store == nil {
		writeJSON(w, http.StatusOK, SettingsDTO{})
		return
	}
	raw, ok, err := s.deps.Store.GetSetting(settingsKey)
	if err != nil || !ok {
		writeJSON(w, http.StatusOK, SettingsDTO{})
		return
	}
	var dto SettingsDTO
	if err := json.Unmarshal([]byte(raw), &dto); err != nil {
		writeJSON(w, http.StatusOK, SettingsDTO{})
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

// putSettings validates, persists and applies the configuration.
func (s *Server) putSettings(w http.ResponseWriter, r *http.Request) {
	var dto SettingsDTO
	if err := decodeJSON(r, &dto); err != nil {
		httpError(w, http.StatusBadRequest, err.Error())
		return
	}
	switch dto.Board.Type {
	case "forcad", "ctfd", "faust":
	default:
		httpError(w, http.StatusBadRequest, "board.type must be forcad|ctfd|faust")
		return
	}
	if dto.Board.URL == "" {
		httpError(w, http.StatusBadRequest, "board.url is required")
		return
	}
	if dto.RoundDurationMinutes <= 0 {
		dto.RoundDurationMinutes = 2
	}
	if dto.FlagRegex == "" {
		dto.FlagRegex = state.DefaultFlagRegex
	}
	if dto.BanFraction <= 0 || dto.BanFraction >= 1 {
		dto.BanFraction = 0.25
	}

	if raw, err := json.Marshal(dto); err == nil && s.deps.Store != nil {
		if err := s.deps.Store.SetSetting(settingsKey, string(raw)); err != nil {
			httpError(w, http.StatusInternalServerError, "persist failed")
			return
		}
	}

	if s.deps.Reconfigure != nil {
		if err := s.deps.Reconfigure(dto); err != nil {
			httpError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}
	s.deps.Hub.Broadcast(Event{
		Type: "settings.applied", Message: "configuration updated", At: timeNow(),
	})
	w.WriteHeader(http.StatusNoContent)
}
