// Package status holds shared enums used by board adapters and engine.
package status

type CheckerStatus int8

const (
	CheckerUnknown CheckerStatus = iota
	CheckerGreen
	CheckerRed
)

func (c CheckerStatus) String() string {
	switch c {
	case CheckerGreen:
		return "green"
	case CheckerRed:
		return "red"
	default:
		return "unknown"
	}
}

func (c CheckerStatus) Green() bool { return c == CheckerGreen }
func (c CheckerStatus) Red() bool   { return c == CheckerRed }

// FromBoardStatus converts a board adapter status string.
func FromBoardStatus(s string) CheckerStatus {
	switch s {
	case "green", "up", "ok", "UP", "GOOD":
		return CheckerGreen
	case "red", "down", "err", "error", "DOWN", "BAD", "MUMBLE", "SHIT":
		return CheckerRed
	default:
		return CheckerUnknown
	}
}
