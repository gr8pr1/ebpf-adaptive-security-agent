package sensitive

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
)

// Matcher resolves configured sensitive paths to inodes and matches open paths.
type Matcher struct {
	mu     sync.RWMutex
	paths  []string
	inodes map[uint64]struct{}
}

func New(paths []string) *Matcher {
	m := &Matcher{
		paths:  append([]string(nil), paths...),
		inodes: make(map[uint64]struct{}),
	}
	m.refreshInodes()
	return m
}

func DefaultPaths() []string {
	return []string{
		"/etc/shadow",
		"/etc/sudoers",
	}
}

func (m *Matcher) Paths() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.paths))
	copy(out, m.paths)
	return out
}

func (m *Matcher) refreshInodes() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inodes = make(map[uint64]struct{})
	for _, p := range m.paths {
		if st, err := os.Stat(p); err == nil {
			if ino := fileInode(st); ino != 0 {
				m.inodes[ino] = struct{}{}
			}
		}
		// authorized_keys under .ssh
		if strings.Contains(p, "authorized_keys") {
			continue
		}
	}
}

// Match returns true if path resolves to a sensitive inode or suffix path.
func (m *Matcher) Match(path string) bool {
	if path == "" {
		return false
	}
	clean := filepath.Clean(path)
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, p := range m.paths {
		if p == "" {
			continue
		}
		if clean == p || strings.HasSuffix(clean, p) {
			return true
		}
		if strings.HasSuffix(p, "authorized_keys") && strings.HasSuffix(clean, "authorized_keys") {
			return true
		}
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		resolved = clean
	}
	if st, err := os.Stat(resolved); err == nil {
		if ino := fileInode(st); ino != 0 {
			if _, ok := m.inodes[ino]; ok {
				return true
			}
		}
	}
	return false
}

func fileInode(st os.FileInfo) uint64 {
	if st == nil {
		return 0
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok {
		return sys.Ino
	}
	return 0
}
