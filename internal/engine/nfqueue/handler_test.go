package nfqueue

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeHandler struct{ verdict Verdict }

func (f *fakeHandler) Handle(p *Packet) Verdict { return f.verdict }

func TestPacketFnAppliesAcceptVerdict(t *testing.T) {
	q := &Queue{nf: nil, handler: &fakeHandler{verdict: Accept}}
	require.NotNil(t, q)
}

func TestVerdictString(t *testing.T) {
	assert.Equal(t, "ACCEPT", Accept.String())
	assert.Equal(t, "DROP", Drop.String())
	assert.Equal(t, "STOLEN", Stolen.String())
}
