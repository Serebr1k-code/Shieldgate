package classifier

import (
	"fmt"
	"testing"
)

func BenchmarkFingerprintHTTP(b *testing.B) {
	payload := []byte("GET /api/user/1234?token=abcdef123456 HTTP/1.1\r\nHost: 10.0.0.1\r\nCookie: session=zzz\r\nUser-Agent: curl/8.5\r\n\r\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		NewFingerprint(payload)
	}
}

func BenchmarkFindOrCreateGroupExact(b *testing.B) {
	m := NewMatcher()
	fp := NewFingerprint([]byte("GET /status HTTP/1.1\r\nHost: x\r\n\r\n"))
	m.FindOrCreateGroup("svc", fp, "seed")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.FindOrCreateGroup("svc", fp, fmt.Sprintf("flow%d", i))
	}
}

func BenchmarkLevenshtein1KB(b *testing.B) {
	a := make([]byte, 1024)
	c := make([]byte, 1024)
	for i := range a {
		a[i] = byte('a' + i%26)
		c[i] = a[i]
	}
	c[999] = 'X'
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		levenshtein(a, c)
	}
}

func BenchmarkRingBufferWrite(b *testing.B) {
	rb := NewRingBuffer(64 * 1024)
	chunk := make([]byte, 1400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.Write(chunk)
	}
}

func BenchmarkSimilarity1KBTemplates(b *testing.B) {
	mk := func(seed byte) []byte {
		p := make([]byte, 0, 1200)
		for i := 0; i < 100; i++ {
			p = append(p, "GET /api/user/12345?token="...)
			for j := 0; j < 10; j++ {
				p = append(p, seed+byte(i%7))
			}
			p = append(p, " HTTP/1.1\r\nHost: h\r\nX-A: b\r\n\r\n"...)
		}
		return p
	}
	f1 := NewFingerprint(mk('a'))
	f2 := NewFingerprint(mk('b'))
	if f1.Hash == f2.Hash {
		b.Fatal("templates unexpectedly identical")
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		f1.Similarity(f2)
	}
}
