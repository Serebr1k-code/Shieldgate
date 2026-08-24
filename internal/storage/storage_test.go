package storage

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func openTestDB(t *testing.T) *DB {
	d, err := Open(filepath.Join(t.TempDir(), "test.db"))
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	return d
}

func TestGroupPersistence(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().UTC().Truncate(time.Second)
	checker := true
	err := db.UpsertGroup(GroupRow{
		ID: "g1", ServiceID: "svc1", Status: 2, IsChecker: &checker,
		Weight: 0.75, BaseWeight: 1.0, Fingerprint: []byte("GET /x"),
		FirstSeen: now, LastSeen: now,
	})
	require.NoError(t, err)

	rows, err := db.LoadGroups("svc1")
	require.NoError(t, err)
	require.Len(t, rows, 1)
	assert.Equal(t, "g1", rows[0].ID)
	assert.InDelta(t, 0.75, rows[0].Weight, 1e-9)
	require.NotNil(t, rows[0].IsChecker)
	assert.True(t, *rows[0].IsChecker)

	// Update on conflict.
	checker = false
	require.NoError(t, db.UpsertGroup(GroupRow{
		ID: "g1", ServiceID: "svc1", Status: 1, IsChecker: &checker,
		Weight: 0.5, BaseWeight: 1.0, FirstSeen: now, LastSeen: now.Add(time.Minute),
	}))
	rows, _ = db.LoadGroups("svc1")
	require.Len(t, rows, 1)
	assert.False(t, *rows[0].IsChecker)
	assert.InDelta(t, 0.5, rows[0].Weight, 1e-9)
}

func TestSettingsRoundtrip(t *testing.T) {
	db := openTestDB(t)
	v, ok, err := db.GetSetting("round_duration")
	require.NoError(t, err)
	assert.False(t, ok)

	require.NoError(t, db.SetSetting("round_duration", "2m"))
	v, ok, err = db.GetSetting("round_duration")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "2m", v)

	require.NoError(t, db.SetSetting("round_duration", "5m"))
	v, _, _ = db.GetSetting("round_duration")
	assert.Equal(t, "5m", v)
}

func TestDecisionsLog(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	require.NoError(t, db.LogDecision(DecisionRow{
		TS: now, ServiceID: "svc1", FlowID: "f1",
		Src: "10.0.0.1:1234", Dst: "10.0.0.9:5000",
		Verdict: "DROP", Reason: "banned group",
	}))
	got, err := db.RecentDecisions(10)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "DROP", got[0].Verdict)
	assert.Equal(t, "banned group", got[0].Reason)
}

func TestFlagsLog(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()
	require.NoError(t, db.LogFlag(now, "svc1", "10.0.0.66:4444", "AAAA1111BBBB2222CCCC3333ddddEE1="))
	got, err := db.RecentFlags(5)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Contains(t, got[0].Flag, "=")
}

func TestPcapWriterFormat(t *testing.T) {
	dir := t.TempDir()
	w, err := NewPcapWriter(dir)
	require.NoError(t, err)
	defer w.Close()

	payload := []byte{0x45, 0x00, 0x00, 0x14} // fake IPv4 header start
	ts := time.Unix(1700000000, 500000000)
	require.NoError(t, w.WritePacket(payload, ts))

	data, err := readFile(w.Path())
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(data), 24+16+len(payload))

	assert.EqualValues(t, 0xd4, data[0], "little-endian pcap magic")
	assert.EqualValues(t, 0xa1, data[3])
	assert.EqualValues(t, 101, binary.LittleEndian.Uint32(data[20:24]), "LINKTYPE_RAW")

	recTS := binary.LittleEndian.Uint32(data[24:28])
	assert.EqualValues(t, 1700000000, recTS)
	usec := binary.LittleEndian.Uint32(data[28:32])
	assert.EqualValues(t, 500000, usec)
	inclLen := binary.LittleEndian.Uint32(data[32:36])
	assert.EqualValues(t, len(payload), inclLen)
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
