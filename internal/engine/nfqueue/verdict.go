package nfqueue

// Verdict is the decision applied to an intercepted packet.
type Verdict int8

const (
	Accept Verdict = iota // NF_ACCEPT
	Drop                  // NF_DROP
	Stolen                // NF_STOLEN (packet mirrored elsewhere)
)

func (v Verdict) String() string {
	switch v {
	case Accept:
		return "ACCEPT"
	case Drop:
		return "DROP"
	case Stolen:
		return "STOLEN"
	default:
		return "UNKNOWN"
	}
}

// Packet is a packet intercepted from the kernel queue.
type Packet struct {
	ID   uint32 // kernel packet id (used for set_verdict)
	Mark uint32
	Data []byte
}
