package policy

import (
	"testing"
	"time"

	"shieldgate/internal/engine/classifier"
)

func BenchmarkEvaluateAllowed(b *testing.B) {
	g := classifier.NewFlowGroup("g", "svc", classifier.NewFingerprint([]byte("x")), time.Now())
	g.SetStatus(classifier.GroupAllowed, time.Now())
	f := &classifier.Flow{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Evaluate(f, g)
	}
}
