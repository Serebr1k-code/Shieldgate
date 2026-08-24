package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthEndpoint(t *testing.T) {
	s := newServerForTest(t)
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	s.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "ok", w.Body.String())
}

func TestListServicesAndMarkGroup(t *testing.T) {
	s := newServerForTest(t)

	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/services", nil))
	require.Equal(t, http.StatusOK, w.Code)

	var svcs []struct {
		ID     string `json:"id"`
		Port   uint16 `json:"port"`
		Phase  string `json:"phase"`
		Groups []struct {
			ID     string  `json:"id"`
			Status string  `json:"status"`
			Weight float64 `json:"weight"`
		} `json:"groups"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &svcs))
	require.Len(t, svcs, 1)
	require.Len(t, svcs[0].Groups, 1)
	gid := svcs[0].Groups[0].ID

	// Mark group as checker traffic.
	body, _ := json.Marshal(map[string]any{"is_checker": true})
	w = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPatch,
		"/api/v1/services/svc1/groups/"+gid, bytes.NewReader(body))
	s.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)

	// Verify persisted.
	w = httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/services", nil))
	var svcs2 []struct {
		Groups []struct {
			Checker *bool `json:"is_checker"`
		} `json:"groups"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &svcs2))
	require.NotNil(t, svcs2[0].Groups[0].Checker)
	assert.True(t, *svcs2[0].Groups[0].Checker)
}

func TestSetGroupStatusManually(t *testing.T) {
	s := newServerForTest(t)

	body, _ := json.Marshal(map[string]string{"status": "banned"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost,
		"/api/v1/groups/nonexistent/status", bytes.NewReader(body))
	s.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestFlowsListing(t *testing.T) {
	s := newServerForTest(t)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/flows?limit=10", nil))
	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, strings.HasPrefix(strings.TrimSpace(w.Body.String()), "["))
}

func TestWebSocketBroadcast(t *testing.T) {
	s, hub := newServerWithHub(t)
	ts := httptest.NewServer(s)
	defer ts.Close()

	url := "ws" + strings.TrimPrefix(ts.URL, "http") + "/ws"
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	require.NoError(t, err)
	defer c.Close()

	deadline := time.Now().Add(2 * time.Second)
	for hub.Count() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	require.Equal(t, 1, hub.Count(), "client must be registered")

	hub.Broadcast(Event{Type: "flag.detected", Message: "test", At: time.Now()})
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, msg, err := c.ReadMessage()
	require.NoError(t, err)
	assert.Contains(t, string(msg), `"type":"flag.detected"`)
}

func TestUnknownRouteIs404(t *testing.T) {
	s := newServerForTest(t)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/nope", nil))
	assert.Equal(t, http.StatusNotFound, w.Code)
}
