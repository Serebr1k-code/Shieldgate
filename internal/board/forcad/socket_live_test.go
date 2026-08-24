package forcad

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestLiveForcADSocket hits the real scoreboard; skipped unless
// SHIELDGATE_LIVE_BOARD is set.
func TestLiveForcADSocket(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	a := NewSocket("https://rctfscoreboard.digital.mephi.ru", map[string]uint16{
		"xingyuan":           5001,
		"battlebots_revenge": 5002,
	})
	a.ourIPStr = "10.70.20.2"

	svcs, err := a.GetServices()
	if err != nil {
		t.Skipf("board unreachable (network?): %v", err)
	}
	require.NotEmpty(t, svcs)
	t.Logf("services: %+v", svcs)

	teams, err := a.GetTeams()
	require.NoError(t, err)
	require.NotEmpty(t, teams)
	assert.Equal(t, "10.70.", teams[0].IP.String()[:6]) // sanity: game network IPs

	statuses, err := a.Poll()
	require.NoError(t, err)
	for id, st := range statuses {
		t.Logf("checker %s = %s", id, st)
	}

	ip, err := a.GetOurIP()
	require.NoError(t, err)
	assert.Equal(t, "10.70.20.2", ip.String())
}
