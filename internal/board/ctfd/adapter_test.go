package ctfd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockCTFd(t *testing.T) *Adapter {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/services", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"data":[{"id":1,"name":"pwn","port":1337,"protocol":"tcp"},{"id":2,"name":"web","port":80}]}`))
	})
	mux.HandleFunc("/api/v1/scoreboard", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"data":[{"team_id":7,"service_statuses":{"pwn":"UP","web":"DOWN"}}]}`))
	})
	mux.HandleFunc("/api/v1/teams", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"data":[{"id":1,"name":"a","ip":"10.60.1.1"},{"id":2,"name":"b","ip":"10.60.2.2"}]}`))
	})
	mux.HandleFunc("/api/v1/team/me", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"success":true,"data":{"id":7,"ip":"10.60.0.7"}}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return New(srv.URL, "tok")
}

func TestCTFdServicesAndStatuses(t *testing.T) {
	a := newMockCTFd(t)
	svcs, err := a.GetServices()
	require.NoError(t, err)
	require.Len(t, svcs, 2)
	assert.Equal(t, "ctfd_pwn", svcs[0].ID)
	st, err := a.GetCheckerStatus("ctfd_pwn")
	require.NoError(t, err)
	assert.True(t, st.Green())
	st, err = a.GetCheckerStatus("ctfd_web")
	require.NoError(t, err)
	assert.True(t, st.Red())
}

func TestCTFdTeamsAndSelfIP(t *testing.T) {
	a := newMockCTFd(t)
	teams, err := a.GetTeams()
	require.NoError(t, err)
	require.Len(t, teams, 2)
	ip, err := a.GetOurIP()
	require.NoError(t, err)
	assert.Equal(t, "10.60.0.7", ip.String())
}
