package forcad

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockForcAD(t *testing.T) *Adapter {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/services", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"name":"My Service","port":5000,"protocol":"tcp"},{"name":"web2","port":8080}]`))
	})
	mux.HandleFunc("/api/checker/my_service", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"up"}`))
	})
	mux.HandleFunc("/api/checker/web2", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status":"down"}`))
	})
	mux.HandleFunc("/api/teams", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"id":1,"name":"team1","ip":"10.10.1.1"},{"id":2,"name":"team2","ip":"10.10.2.2"}]`))
	})
	mux.HandleFunc("/api/team/self", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Token secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"id":7,"name":"us","ip":"10.10.0.7"}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return New(srv.URL, "secret")
}

func TestForcADGetServices(t *testing.T) {
	a := newMockForcAD(t)
	svcs, err := a.GetServices()
	require.NoError(t, err)
	require.Len(t, svcs, 2)
	assert.Equal(t, "forcad_my_service", svcs[0].ID)
	assert.EqualValues(t, 5000, svcs[0].Port)
	assert.Equal(t, "tcp", svcs[0].Protocol, "default protocol")
}

func TestForcADCheckerStatuses(t *testing.T) {
	a := newMockForcAD(t)
	st, err := a.GetCheckerStatus("forcad_my_service")
	require.NoError(t, err)
	assert.True(t, st.Green())
	st, err = a.GetCheckerStatus("forcad_web2")
	require.NoError(t, err)
	assert.True(t, st.Red())
}

func TestForcADTeamsAndSelfIP(t *testing.T) {
	a := newMockForcAD(t)
	teams, err := a.GetTeams()
	require.NoError(t, err)
	require.Len(t, teams, 2)
	ip, err := a.GetOurIP()
	require.NoError(t, err)
	assert.Equal(t, "10.10.0.7", ip.String())
}
