package proctable

import (
	"sync"
	"time"

	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/ringbuf"
)

// Identity is a reuse-safe process identity (pid + start time).
type Identity struct {
	PID     uint32
	StartNS uint64
}

// Entry holds process metadata for lineage walks.
type Entry struct {
	Identity Identity
	PPID     uint32
	Binary   string
	Comm     string
	LastSeen time.Time
	Exited   bool
}

// Table tracks processes from fork/exec/exit for lineage and composite rules.
type Table struct {
	mu      sync.RWMutex
	byPID   map[uint32]*Entry
	startNS map[uint32]uint64
}

func New() *Table {
	return &Table{
		byPID:   make(map[uint32]*Entry),
		startNS: make(map[uint32]uint64),
	}
}

func (t *Table) Observe(ev *enricher.EnrichedEvent) {
	if t == nil || ev == nil || ev.Raw == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	raw := ev.Raw

	switch raw.EventType {
	case ringbuf.EventFork:
		start := raw.TimestampNs
		if start == 0 {
			start = uint64(now.UnixNano())
		}
		t.startNS[raw.PID] = start
		t.byPID[raw.PID] = &Entry{
			Identity: Identity{PID: raw.PID, StartNS: start},
			PPID:     raw.PPID,
			Binary:   ev.Binary,
			Comm:     raw.CommString(),
			LastSeen: now,
		}
	case ringbuf.EventExec:
		start, ok := t.startNS[raw.PID]
		if !ok {
			start = raw.TimestampNs
			if start == 0 {
				start = uint64(now.UnixNano())
			}
			t.startNS[raw.PID] = start
		}
		e, exists := t.byPID[raw.PID]
		if !exists {
			e = &Entry{Identity: Identity{PID: raw.PID, StartNS: start}, PPID: raw.PPID}
			t.byPID[raw.PID] = e
		}
		e.Binary = ev.Binary
		e.Comm = raw.CommString()
		e.LastSeen = now
		e.Exited = false
	case ringbuf.EventExit:
		if e, ok := t.byPID[raw.PID]; ok {
			e.Exited = true
			e.LastSeen = now
		}
		delete(t.startNS, raw.PID)
	default:
		if e, ok := t.byPID[raw.PID]; ok {
			e.LastSeen = now
			if ev.Binary != "" {
				e.Binary = ev.Binary
			}
		}
	}
}

// Lineage returns ancestors from immediate parent upward (max depth).
func (t *Table) Lineage(pid uint32, maxDepth int) []*Entry {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var out []*Entry
	cur, ok := t.byPID[pid]
	if !ok {
		return nil
	}
	ppid := cur.PPID
	for i := 0; i < maxDepth && ppid > 0; i++ {
		parent, ok := t.byPID[ppid]
		if !ok {
			break
		}
		out = append(out, parent)
		ppid = parent.PPID
	}
	return out
}

// EntryFor returns the table entry for a pid if present.
func (t *Table) EntryFor(pid uint32) (*Entry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.byPID[pid]
	return e, ok
}

// Prune removes exited entries older than maxAge.
func (t *Table) Prune(maxAge time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	for pid, e := range t.byPID {
		if e.Exited && e.LastSeen.Before(cutoff) {
			delete(t.byPID, pid)
		}
	}
}
