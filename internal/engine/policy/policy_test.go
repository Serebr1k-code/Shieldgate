package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"shieldgate/internal/engine/classifier"
	"shieldgate/internal/engine/nfqueue"
)

func mkGroup(status classifier.GroupStatus, checker bool) *classifier.FlowGroup {
	g := classifier.NewFlowGroup("g", "svc", classifier.NewFingerprint([]byte("x")), time.Now())
	g.SetStatus(status, time.Now())
	v := checker
	g.IsChecker = &v
	return g
}

func mkFlow(flagSeen bool) *classifier.Flow {
	f := &classifier.Flow{FlagSeen: flagSeen}
	return f
}

func TestPolicyFlagSeenDropsAndResets(t *testing.T) {
	d := Evaluate(mkFlow(true), mkGroup(classifier.GroupAllowed, false))
	assert.Equal(t, nfqueue.Drop, d.Verdict)
	assert.True(t, d.SendRST)
	assert.False(t, d.Mirror, "flag traffic must never be mirrored")
}

func TestPolicyBannedGroup(t *testing.T) {
	d := Evaluate(mkFlow(false), mkGroup(classifier.GroupBanned, false))
	assert.Equal(t, nfqueue.Drop, d.Verdict)
	assert.True(t, d.SendRST)
	assert.True(t, d.Mirror)
}

func TestPolicyTempBannedGroupNoRSTNoMirror(t *testing.T) {
	d := Evaluate(mkFlow(false), mkGroup(classifier.GroupTempBanned, false))
	assert.Equal(t, nfqueue.Drop, d.Verdict)
	assert.False(t, d.SendRST, "temp-ban must not RST (checker may reconnect)")
	assert.False(t, d.Mirror, "temp-ban must not be mirrored")
}

func TestPolicyAllowedGroupAccepts(t *testing.T) {
	d := Evaluate(mkFlow(false), mkGroup(classifier.GroupAllowed, false))
	assert.Equal(t, nfqueue.Accept, d.Verdict)

	d = Evaluate(mkFlow(false), mkGroup(classifier.GroupAllowed, true))
	assert.Equal(t, nfqueue.Accept, d.Verdict)
}

func TestPolicyUnknownConservativeDrop(t *testing.T) {
	d := Evaluate(mkFlow(false), nil)
	assert.Equal(t, nfqueue.Drop, d.Verdict)

	d = Evaluate(mkFlow(false), mkGroup(classifier.GroupCandidate, false))
	assert.Equal(t, nfqueue.Drop, d.Verdict)
}
