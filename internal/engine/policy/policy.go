// Package policy maps flow/group state to NFQUEUE verdicts.
package policy

import (
	"shieldgate/internal/engine/classifier"
	"shieldgate/internal/engine/nfqueue"
	"shieldgate/internal/status"
)

// Decision is the full outcome of the policy evaluation for one packet.
type Decision struct {
	Verdict nfqueue.Verdict
	SendRST bool   // terminate connection after drop
	Mirror  bool   // mirror packet to other teams
	Reason  string // human-readable explanation for logs/UI
}

// Evaluate applies the ShieldGate ruleset to a flow.
//
// Priority order:
//  1. Flag seen in payload        -> DROP + RST, never mirrored
//  2. Group Banned                -> DROP + RST, mirrored
//  3. Group TempBanned (1/4 test) -> DROP silently, never mirrored
//  4. Group Allowed               -> ACCEPT
//  5. Unknown / Candidate         -> DROP (conservative)
func Evaluate(flow *classifier.Flow, group *classifier.FlowGroup) Decision {
	switch {
	case flow != nil && flow.FlagSeen:
		return Decision{Verdict: nfqueue.Drop, SendRST: true, Mirror: false,
			Reason: "flag detected"}

	case group == nil:
		return Decision{Verdict: nfqueue.Drop, Reason: "no matching group"}

	default:
		switch group.GetStatus() {
		case classifier.GroupBanned:
			return Decision{Verdict: nfqueue.Drop, SendRST: true, Mirror: true,
				Reason: "banned group"}
		case classifier.GroupTempBanned:
			return Decision{Verdict: nfqueue.Drop, Mirror: false,
				Reason: "temp-banned group (1/4 test)"}
		case classifier.GroupAllowed:
			if checkerMarked(group) {
				return Decision{Verdict: nfqueue.Accept, Reason: "checker-marked group"}
			}
			return Decision{Verdict: nfqueue.Accept, Reason: "allowed group"}
		default: // Candidate / unknown
			return Decision{Verdict: nfqueue.Drop, Reason: "unclassified traffic"}
		}
	}
}

func checkerMarked(g *classifier.FlowGroup) bool {
	return g.IsChecker != nil && *g.IsChecker
}

// CheckerToFlowStatus is a helper bridging board statuses into UI labels.
func CheckerLabel(st status.CheckerStatus) string { return st.String() }
