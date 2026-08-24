package faust

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockFAUST(t *testing.T) *Adapter {
	mux := http.NewServeMux()
	mux.HandleFunc("/scoreboard", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"teams":[{"id":1,"name":"team1","ip":"10.70.1.1"},{"id":2,"name":"team2","ip":"10.70.2.2"}],
			"services":[{"name":"dummy","port":5000,"protocol":"tcp"},{"name":"web","port":8080}]
		}`))
	})
	mux.HandleFunc("/service_status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"services":{"dummy":"GOOD","web":"MUMBLE"}}`))
	})
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"team_ip":"10.70.0.9"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return New(srv.URL)
}

func TestFAUSTServicesAndStatuses(t *testing.T) {
	a := newMockFAUST(t)
	svcs, err := a.GetServices()
	require.NoError(t, err)
	require.Len(t, svcs, 2)
	assert.Equal(t, "faust_dummy", svcs[0].ID)
	st, err := a.GetCheckerStatus("faust_dummy")
	require.NoError(t, err)
	assert.True(t, st.Green())
	st, err = a.GetCheckerStatus("faust_web")
	require.NoError(t, err)
	assert.True(t, st.Red(), "MUMBLE must map to red")
}

func TestFAUSTTeamsAndSelfIP(t *testing.T) {
	a := newMockFAUST(t)
	teams, err := a.GetTeams()
	require.NoError(t, err)
	require.Len(t, teams, 2)
	ip, err := a.GetOurIP()
	require.NoError(t, err)
	assert.Equal(t, "10.70.0.9", ip.String())
}

func TestFAUSTPollAllServices(t *testing.T) {
	a := newMockFAUST(t)
	statuses, err := a.Poll()
	require.NoError(t, err)
	require.Len(t, statuses, 2)
	assert.True(t, statuses["faust_dummy"].Green())
}
