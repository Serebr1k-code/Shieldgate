// Package storage persists flows/groups/settings to SQLite and dumps
// traffic segments as pcap files.
package storage

import (
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

// DB wraps the SQLite handle.
type DB struct {
	db *sql.DB
}

func Open(path string) (*DB, error) {
	db, err := sql.Open("sqlite3", path+"?_busy_timeout=5000&_journal_mode=WAL")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // sqlite single-writer
	d := &DB{db: db}
	if err := d.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return d, nil
}

func (d *DB) Close() error { return d.db.Close() }

func (d *DB) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS flow_groups (
	id TEXT PRIMARY KEY,
	service_id TEXT NOT NULL,
	status INTEGER NOT NULL DEFAULT 0,
	is_checker INTEGER,           -- NULL = unknown
	weight REAL NOT NULL DEFAULT 1.0,
	base_weight REAL NOT NULL DEFAULT 1.0,
	fingerprint BLOB,
	first_seen TIMESTAMP NOT NULL,
	last_seen TIMESTAMP NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_groups_service ON flow_groups(service_id);

CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS decisions (
	ts TIMESTAMP NOT NULL,
	service_id TEXT NOT NULL,
	flow_id TEXT NOT NULL,
	src TEXT NOT NULL, dst TEXT NOT NULL,
	verdict TEXT NOT NULL, reason TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_decisions_ts ON decisions(ts DESC);

CREATE TABLE IF NOT EXISTS flags (
	ts TIMESTAMP NOT NULL,
	service_id TEXT NOT NULL,
	src TEXT NOT NULL,
	flag TEXT NOT NULL
);
`
	_, err := d.db.Exec(schema)
	return err
}

// --- FlowGroup persistence ---

type GroupRow struct {
	ID          string
	ServiceID   string
	Status      int8
	IsChecker   *bool
	Weight      float64
	BaseWeight  float64
	Fingerprint []byte
	FirstSeen   time.Time
	LastSeen    time.Time
}

func (d *DB) UpsertGroup(g GroupRow) error {
	_, err := d.db.Exec(`
INSERT INTO flow_groups (id, service_id, status, is_checker, weight, base_weight, fingerprint, first_seen, last_seen)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(id) DO UPDATE SET status=excluded.status, is_checker=excluded.is_checker,
 weight=excluded.weight, base_weight=excluded.base_weight, last_seen=excluded.last_seen`,
		g.ID, g.ServiceID, g.Status, g.IsChecker, g.Weight, g.BaseWeight,
		g.Fingerprint, g.FirstSeen.UTC(), g.LastSeen.UTC())
	return err
}

func (d *DB) LoadGroups(serviceID string) ([]GroupRow, error) {
	rows, err := d.db.Query(`
SELECT id, service_id, status, is_checker, weight, base_weight, fingerprint, first_seen, last_seen
FROM flow_groups WHERE service_id = ?`, serviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []GroupRow
	for rows.Next() {
		var r GroupRow
		var fp sql.RawBytes
		if err := rows.Scan(&r.ID, &r.ServiceID, &r.Status, &r.IsChecker,
			&r.Weight, &r.BaseWeight, &fp, &r.FirstSeen, &r.LastSeen); err != nil {
			return nil, err
		}
		if fp != nil {
			r.Fingerprint = append([]byte(nil), fp...)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Settings ---

func (d *DB) SetSetting(key, value string) error {
	_, err := d.db.Exec(`
INSERT INTO settings (key, value) VALUES (?, ?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (d *DB) GetSetting(key string) (string, bool, error) {
	var v string
	err := d.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

// --- Decisions log ---

type DecisionRow struct {
	TS        time.Time
	ServiceID string
	FlowID    string
	Src, Dst  string
	Verdict   string
	Reason    string
}

func (d *DB) LogDecision(r DecisionRow) error {
	_, err := d.db.Exec(`INSERT INTO decisions (ts, service_id, flow_id, src, dst, verdict, reason)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		r.TS.UTC(), r.ServiceID, r.FlowID, r.Src, r.Dst, r.Verdict, r.Reason)
	return err
}

func (d *DB) RecentDecisions(limit int) ([]DecisionRow, error) {
	rows, err := d.db.Query(`SELECT ts, service_id, flow_id, src, dst, verdict, reason
FROM decisions ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []DecisionRow
	for rows.Next() {
		var r DecisionRow
		if err := rows.Scan(&r.TS, &r.ServiceID, &r.FlowID, &r.Src, &r.Dst, &r.Verdict, &r.Reason); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- Flag hits ---

func (d *DB) LogFlag(ts time.Time, serviceID, src, flag string) error {
	_, err := d.db.Exec(`INSERT INTO flags (ts, service_id, src, flag) VALUES (?, ?, ?, ?)`,
		ts.UTC(), serviceID, src, flag)
	return err
}
func (d *DB) RecentFlags(limit int) ([]FlagRow, error) {
	rows, err := d.db.Query(`SELECT ts, service_id, src, flag FROM flags ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FlagRow
	for rows.Next() {
		var r FlagRow
		if err := rows.Scan(&r.TS, &r.ServiceID, &r.Src, &r.Flag); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type FlagRow struct {
	TS        time.Time
	ServiceID string
	Src       string
	Flag      string
}
