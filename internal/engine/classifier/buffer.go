package classifier

import (
	"bytes"
)

// RingBuffer keeps the last `size` bytes written.
type RingBuffer struct {
	buf  []byte
	size int
}

func NewRingBuffer(size int) *RingBuffer {
	return &RingBuffer{buf: make([]byte, 0, size), size: size}
}

func (r *RingBuffer) Write(p []byte) (n int, err error) {
	n = len(p)
	if r.size <= 0 {
		return n, nil
	}
	if n >= r.size {
		r.buf = append(r.buf[:0], p[n-r.size:]...)
		return n, nil
	}
	free := r.size - len(r.buf)
	if n > free {
		copy(r.buf, r.buf[n:])
		r.buf = r.buf[:len(r.buf)-n]
	}
	r.buf = append(r.buf, p...)
	return n, nil
}

func (r *RingBuffer) Bytes() []byte { return append([]byte(nil), r.buf...) }

func (r *RingBuffer) Len() int { return len(r.buf) }

// Contains reports whether b is a substring of the buffered data.
func (r *RingBuffer) Contains(b []byte) bool { return bytes.Contains(r.buf, b) }
