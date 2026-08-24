package state

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlagDetectorDefaultRegex(t *testing.T) {
	d, err := NewFlagDetector("")
	require.NoError(t, err)
	assert.True(t, d.Scan([]byte("GET / HTTP/1.1\r\n\r\nAAAA1111BBBB2222CCCC3333ddddEE1=")))
	assert.False(t, d.Scan([]byte("nothing to see here")))
	flags := d.Find([]byte("flag is 01234567890123456789012345678901= ok"))
	require.Len(t, flags, 1)
}

func TestFlagDetectorCustomPattern(t *testing.T) {
	d, err := NewFlagDetector(`FLAG\{[^}]+\}`)
	require.NoError(t, err)
	assert.True(t, d.Scan([]byte("x FLAG{abc} y")))
	assert.False(t, d.Scan([]byte("x FLAG{abc y")))
}

func TestFlagDetectorSetPattern(t *testing.T) {
	d, err := NewFlagDetector("")
	require.NoError(t, err)
	require.NoError(t, d.SetPattern("zzz"))
	assert.False(t, d.Scan([]byte("hello")))
	assert.True(t, d.Scan([]byte("zzz")))
	require.Error(t, d.SetPattern("("))
}
