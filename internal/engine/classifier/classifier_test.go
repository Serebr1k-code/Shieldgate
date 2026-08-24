package classifier

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeHTTPSameGroup(t *testing.T) {
	r1 := []byte("GET /api/user/42?token=abc123 HTTP/1.1\r\nHost: 10.0.0.1\r\nCookie: session=xyz; other=1\r\nUser-Agent: curl/8\r\n\r\n")
	r2 := []byte("GET /api/user/77?token=zzz999 HTTP/1.1\r\nHost: 10.10.10.10\r\nCookie: session=aaa\r\nUser-Agent: python-requests\r\n\r\n")
	f1 := NewFingerprint(r1)
	f2 := NewFingerprint(r2)
	assert.Equal(t, f1.Hash, f2.Hash, "same shape requests must produce identical fingerprints")
}

func TestNormalizeHTTPDifferentPaths(t *testing.T) {
	f1 := NewFingerprint([]byte("GET /api/user HTTP/1.1\r\nHost: h\r\n\r\n"))
	f2 := NewFingerprint([]byte("POST /api/login HTTP/1.1\r\nHost: h\r\n\r\n"))
	assert.NotEqual(t, f1.Hash, f2.Hash)
}

func TestSimilarityFuzzy(t *testing.T) {
	f1 := NewFingerprint([]byte("GET /api/items?limit=10&token=aaa HTTP/1.1\r\nAccept: */*\r\n\r\n"))
	// Slightly different path -> fuzzy match should still be high.
	f2 := NewFingerprint([]byte("GET /api/itemz?limit=10&token=bbb HTTP/1.1\r\nAccept: */*\r\n\r\n"))
	sim := f1.Similarity(f2)
	assert.GreaterOrEqual(t, sim, SimilarityThreshold, "similarity=%v", sim)

	f3 := NewFingerprint([]byte("POST /totally/different HTTP/1.1\r\n\r\n"))
	assert.Less(t, f1.Similarity(f3), SimilarityThreshold)
}

func TestMatcherTenRequestsOneGroup(t *testing.T) {
	m := NewMatcher()
	for i := 0; i < 10; i++ {
		req := []byte("GET /api/status?token=tok" + string(rune('a'+i)) + " HTTP/1.1\r\nHost: x\r\n\r\n")
		fp := NewFingerprint(req)
		g := m.FindOrCreateGroup("svc", fp, "flow"+string(rune('a'+i)))
		require.NotNil(t, g)
		_ = g
	}
	assert.Equal(t, 1, m.Count(), "10 similar requests must collapse into 1 group")
}

func TestMatcherDifferentRequestsSeparateGroups(t *testing.T) {
	m := NewMatcher()
	paths := []string{"/api/user/profile", "/api/orders/list", "/api/auth/login", "/api/admin/settings", "/health/check"}
	for _, p := range paths {
		fp := NewFingerprint([]byte("GET " + p + " HTTP/1.1\r\nHost: x\r\n\r\n"))
		m.FindOrCreateGroup("svc", fp, p)
	}
	assert.Equal(t, 5, m.Count())
}

func TestFlowManagerObserveAndCleanup(t *testing.T) {
	m := NewManager(time.Minute, 4096)
	now := time.Now()
	m.SetClock(func() time.Time { return now })

	src := net.ParseIP("10.1.0.5")
	dst := net.ParseIP("10.1.0.99")
	f := m.Observe(6, src, dst, 44444, 8080, "svc_web", []byte("hello"), Inbound)
	require.NotNil(t, f)
	assert.Equal(t, uint64(5), f.BytesIn)
	assert.Equal(t, 5, f.PayloadIn.Len())

	// Same tuple again accumulates.
	m.Observe(6, src, dst, 44444, 8080, "svc_web", []byte(" world"), Inbound)
	got, ok := m.Get(f.ID)
	require.True(t, ok)
	assert.Equal(t, 11, got.PayloadIn.Len())

	// Opposite direction counts as outbound.
	m.Observe(6, dst, src, 8080, 44444, "svc_web", []byte("resp"), Outbound)
	got, _ = m.Get(f.ID)
	assert.Equal(t, uint64(4), got.BytesOut)

	// Advance past TTL and cleanup.
	now = now.Add(2 * time.Minute)
	expired := m.Cleanup()
	require.Len(t, expired, 1)
	assert.Equal(t, 0, m.Count())
}

func TestRingBufferKeepsTail(t *testing.T) {
	rb := NewRingBuffer(4)
	rb.Write([]byte("abcdefgh"))
	assert.Equal(t, []byte("efgh"), rb.Bytes())
	assert.True(t, rb.Contains([]byte("fgh")))
	assert.False(t, rb.Contains([]byte("abcd")))
}

func TestGroupPenalizeAndReset(t *testing.T) {
	g := NewFlowGroup("g1", "svc", nil, time.Now())
	g.Penalize(0.25) // 1.0 -> 0.75 (multiplicative, -25% of remaining)
	assert.InDelta(t, 0.75, g.Weight, 1e-9)
	prev := g.Weight
	for i := 0; i < 5; i++ {
		g.Penalize(0.25)
		assert.LessOrEqual(t, g.Weight, prev)
		assert.GreaterOrEqual(t, g.Weight, 0.1)
		prev = g.Weight
	}
	// Floor kicks in for small weights.
	g.BaseWeight = 0.13
	g.ResetWeights()
	g.Penalize(0.25)
	assert.InDelta(t, 0.1, g.Weight, 1e-9)
	g.ResetWeights()
	assert.InDelta(t, 0.13, g.Weight, 1e-9)
}
