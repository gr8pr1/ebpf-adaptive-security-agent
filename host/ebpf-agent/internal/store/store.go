package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"ebpf-agent/internal/baseline"

	_ "modernc.org/sqlite"
)

// Store persists baseline snapshots to SQLite.
type Store struct {
	db   *sql.DB
	path string
}

func New(path string) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("creating state directory: %w", err)
	}

	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	if _, err := db.Exec(`PRAGMA journal_mode=WAL`); err != nil {
		db.Close()
		return nil, fmt.Errorf("enabling WAL: %w", err)
	}
	if _, err := db.Exec(`PRAGMA busy_timeout=5000`); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting busy timeout: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS baselines (
			id INTEGER PRIMARY KEY,
			data TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating table: %w", err)
	}

	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS metadata (
			key TEXT PRIMARY KEY,
			value TEXT NOT NULL
		)
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("creating metadata table: %w", err)
	}

	if err := os.Chmod(path, 0600); err != nil && !os.IsNotExist(err) {
		// DB file is created on first write; chmod again after first save if needed.
		_ = err
	}

	return &Store{db: db, path: path}, nil
}

func (s *Store) SaveBaseline(snaps []baseline.DimensionSnapshot) error {
	data, err := json.Marshal(snaps)
	if err != nil {
		return fmt.Errorf("marshaling baseline: %w", err)
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM baselines"); err != nil {
		return err
	}

	if _, err := tx.Exec("INSERT INTO baselines (data) VALUES (?)", string(data)); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	if s.path != "" {
		_ = os.Chmod(s.path, 0600)
	}
	return nil
}

func (s *Store) LoadBaseline() ([]baseline.DimensionSnapshot, error) {
	var data string
	err := s.db.QueryRow("SELECT data FROM baselines ORDER BY id DESC LIMIT 1").Scan(&data)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading baseline: %w", err)
	}

	var snaps []baseline.DimensionSnapshot
	if err := json.Unmarshal([]byte(data), &snaps); err != nil {
		return nil, fmt.Errorf("unmarshaling baseline: %w", err)
	}

	return snaps, nil
}

func (s *Store) SetMeta(key, value string) error {
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
		key, value,
	)
	return err
}

func (s *Store) GetMeta(key string) (string, error) {
	var value string
	err := s.db.QueryRow("SELECT value FROM metadata WHERE key = ?", key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return value, err
}

func (s *Store) Close() error {
	return s.db.Close()
}
