package state

import (
	"math/rand"
	"time"

	"shieldgate/internal/engine/classifier"
)

func NewFlowGroupFixture(id string, weight float64, now time.Time) *classifier.FlowGroup {
	g := classifier.NewFlowGroup(id, "svc", classifier.NewFingerprint([]byte("x")), now)
	g.Weight = weight
	return g
}

func newSeededRand(seed int) *rand.Rand {
	return rand.New(rand.NewSource(int64(seed)))
}
