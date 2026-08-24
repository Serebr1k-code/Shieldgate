package state

import "shieldgate/internal/status"

// CheckerStatus is re-exported for convenience.
type CheckerStatus = status.CheckerStatus

const (
	CheckerUnknown = status.CheckerUnknown
	CheckerGreen   = status.CheckerGreen
	CheckerRed     = status.CheckerRed
)

// FromBoardStatus converts a board adapter status string.
var FromBoardStatus = status.FromBoardStatus
