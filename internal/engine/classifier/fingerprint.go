package classifier

import (
	"crypto/sha256"
	"regexp"
	"strings"
)

var (
	reQueryValue   = regexp.MustCompile(`([?&][A-Za-z0-9_\-]+)=([^&\s]*)`)
	reAuthHeader   = regexp.MustCompile(`(?im)^(Authorization|Cookie|Set-Cookie|X-CSRF-Token|X-Auth-Token|Session):[^\r\n]*`)
	reHeaderValues = regexp.MustCompile(`(?m)^([A-Za-z0-9\-]+):\s+[^\r\n]*`)
	reIPv4         = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
	reTimestamp    = regexp.MustCompile(`(?i)\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b`)
	reHexID        = regexp.MustCompile(`\b[0-9a-fA-F]{16,}\b`)
	rePathID       = regexp.MustCompile(`/\d+`)
)

// NormalizePayload strips dynamic data from a payload producing a stable
// structural template used for grouping.
func NormalizePayload(payload []byte) []byte {
	s := string(payload)
	if isHTTP(s) {
		return []byte(normalizeHTTP(s))
	}
	return normalizeBinary(payload)
}

func isHTTP(s string) bool {
	if len(s) < 8 {
		return false
	}
	methods := []string{"GET ", "POST ", "PUT ", "DELETE ", "PATCH ", "HEAD ", "OPTIONS ", "HTTP/"}
	for _, m := range methods {
		if strings.HasPrefix(s, m) {
			return true
		}
	}
	return false
}

func normalizeHTTP(s string) []byte {
	lines := strings.SplitN(s, "\n", 2)
	requestLine := lines[0]
	rest := ""
	if len(lines) == 2 {
		rest = lines[1]
	}
	// Normalize query parameter values and numeric path IDs.
	requestLine = reQueryValue.ReplaceAllString(requestLine, "$1={}")
	requestLine = rePathID.ReplaceAllString(requestLine, "/{}")
	// Strip sensitive headers entirely.
	rest = reAuthHeader.ReplaceAllString(rest, "$1: {}")
	// Replace header values with placeholders (keep names for structure).
	rest = reHeaderValues.ReplaceAllString(rest, "$1: {}")
	out := requestLine + "\n" + rest
	out = reIPv4.ReplaceAllString(out, "{IP}")
	out = reTimestamp.ReplaceAllString(out, "{TIME}")
	out = reHexID.ReplaceAllString(out, "{HEX}")
	return []byte(out)
}

// normalizeBinary keeps the first 32 bytes as a command signature and
// masks everything after them.
func normalizeBinary(payload []byte) []byte {
	const sigLen = 32
	if len(payload) <= sigLen {
		return append([]byte(nil), payload...)
	}
	sig := append([]byte(nil), payload[:sigLen]...)
	return append(sig, []byte("{BODY}")...)
}

// Fingerprint is the grouping key derived from normalized payloads.
type Fingerprint struct {
	RequestTemplate []byte
	Method          string
	PathPattern     string
	Hash            [32]byte
}

// NewFingerprint builds a fingerprint from a request payload.
func NewFingerprint(requestPayload []byte) *Fingerprint {
	tpl := NormalizePayload(requestPayload)
	f := &Fingerprint{
		RequestTemplate: tpl,
		Method:          extractMethod(requestPayload),
		PathPattern:     extractPathPattern(requestPayload),
	}
	f.Hash = sha256.Sum256(tpl)
	return f
}

func extractMethod(payload []byte) string {
	first := strings.SplitN(string(payload), "\n", 2)[0]
	fields := strings.Fields(first)
	if len(fields) >= 1 && len(fields[0]) <= 8 {
		return fields[0]
	}
	return ""
}

func extractPathPattern(payload []byte) string {
	first := strings.SplitN(string(payload), "\n", 2)[0]
	fields := strings.Fields(first)
	if len(fields) >= 2 {
		path := fields[1]
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i] + "?{}"
		}
		return path
	}
	return ""
}

// maxCompareBytes caps template comparison cost; templates longer than this
// are truncated before similarity computation.
const maxCompareBytes = 512

// Similarity returns [0..1] similarity between two fingerprints based on
// their normalized templates (Levenshtein ratio).
func (f *Fingerprint) Similarity(other *Fingerprint) float64 {
	if f == nil || other == nil {
		return 0
	}
	if f.Hash == other.Hash {
		return 1
	}
	a, b := f.RequestTemplate, other.RequestTemplate
	if len(a) > maxCompareBytes {
		a = a[:maxCompareBytes]
	}
	if len(b) > maxCompareBytes {
		b = b[:maxCompareBytes]
	}
	maxLen := max(len(a), len(b))
	if maxLen == 0 {
		return 1
	}
	// Cheap prefilter: even a perfect alignment of the shorter string
	// cannot exceed this bound.
	if d := maxLen - min(len(a), len(b)); 1-float64(d)/float64(maxLen) < SimilarityThresholdCandidate {
		return 0
	}
	return 1 - float64(levenshtein(a, b))/float64(maxLen)
}

const SimilarityThresholdCandidate = 0.85 // mirrors matcher.SimilarityThreshold

func levenshtein(a, b []byte) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	prev := make([]int, lb+1)
	cur := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		cur[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			cur[j] = min(min(cur[j-1]+1, prev[j]+1), prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[lb]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
