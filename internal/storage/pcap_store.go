package storage

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"time"
)

// PcapWriter writes captured payload segments as pcap files, one per
// service per session. Format: classic libpcap (LINKTYPE_RAW = 101).
type PcapWriter struct {
	f    *os.File
	path string
}

const pcapMagic = 0xa1b2c3d4

func NewPcapWriter(dir string) (*PcapWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	name := filepath.Join(dir, "session_"+time.Now().UTC().Format("20060102_150405")+".pcap")
	f, err := os.Create(name)
	if err != nil {
		return nil, err
	}
	w := &PcapWriter{f: f, path: name}
	if err := w.writeHeader(); err != nil {
		f.Close()
		return nil, err
	}
	return w, nil
}

func (w *PcapWriter) writeHeader() error {
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:], pcapMagic)
	binary.LittleEndian.PutUint16(hdr[4:], 2) // version major
	binary.LittleEndian.PutUint16(hdr[6:], 4) // version minor
	binary.LittleEndian.PutUint32(hdr[12:], 0)
	hdr[16] = 0xff // snaplen low byte; keep simple
	binary.LittleEndian.PutUint32(hdr[16:], 0xFFFF)
	binary.LittleEndian.PutUint32(hdr[20:], 101) // LINKTYPE_RAW (IP)
	_, err := w.f.Write(hdr[:])
	return err
}

// WritePacket appends one raw IP packet record.
func (w *PcapWriter) WritePacket(data []byte, ts time.Time) error {
	var rec [16]byte
	binary.LittleEndian.PutUint32(rec[0:], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(rec[4:], uint32(ts.Nanosecond()/1000))
	binary.LittleEndian.PutUint32(rec[8:], uint32(len(data)))
	binary.LittleEndian.PutUint32(rec[12:], uint32(len(data)))
	if _, err := w.f.Write(rec[:]); err != nil {
		return err
	}
	_, err := w.f.Write(data)
	return err
}

func (w *PcapWriter) Close() error { return w.f.Close() }

func (w *PcapWriter) Path() string { return w.path }
