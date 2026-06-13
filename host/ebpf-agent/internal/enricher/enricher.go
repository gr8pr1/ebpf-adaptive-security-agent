package enricher

import (
	"container/list"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"ebpf-agent/internal/ringbuf"
	"ebpf-agent/internal/sensitive"
)

type EnrichedEvent struct {
	Raw       *ringbuf.Event
	Binary    string
	Username  string
	Container string
	Resolved  bool
	MitreTags []string
}

type pidEntry struct {
	binary  string
	expires time.Time
}

const (
	pidCacheMaxSize   = 4096
	pidCacheTTL       = 10 * time.Second
	userCacheRefresh  = 60 * time.Second
	cgroupCacheMax    = 4096
	cgroupCacheTTL    = 30 * time.Second
)

type Enricher struct {
	cgroupRoot string
	sensitive  *sensitive.Matcher

	userCache     map[uint32]string
	userMu        sync.RWMutex
	lastUserLoad  time.Time

	pidCache map[uint32]*list.Element
	pidOrder *list.List
	pidMu    sync.Mutex

	cgroupCache map[uint64]cgroupEntry
	cgroupMu    sync.Mutex
}

type cgroupEntry struct {
	name    string
	expires time.Time
}

func New(cgroupRoot string, sensitivePaths []string) *Enricher {
	paths := sensitivePaths
	if len(paths) == 0 {
		paths = sensitive.DefaultPaths()
	}
	e := &Enricher{
		cgroupRoot:  cgroupRoot,
		sensitive:   sensitive.New(paths),
		userCache:   make(map[uint32]string),
		pidCache:    make(map[uint32]*list.Element),
		pidOrder:    list.New(),
		cgroupCache: make(map[uint64]cgroupEntry),
	}
	e.loadUsers()
	return e
}

func (e *Enricher) Enrich(ev *ringbuf.Event) *EnrichedEvent {
	var binary string
	var resolved bool
	if ev.EventType == ringbuf.EventExec && ev.Filename != "" {
		binary = ev.Filename
		resolved = true
	} else {
		binary, resolved = e.resolveBinary(ev.PID)
	}

	out := &EnrichedEvent{
		Raw:       ev,
		Binary:    binary,
		Username:  e.resolveUser(ev.UID),
		Container: e.resolveContainer(ev.PID, ev.CgroupID),
		Resolved:  resolved,
	}

	if ev.EventType == ringbuf.EventOpenat && ev.OpenPath() != "" && e.sensitive != nil {
		if e.sensitive.Match(ev.OpenPath()) {
			out.Raw.Flags |= ringbuf.FlagSensitiveFile
		}
	}
	return out
}

func (e *Enricher) resolveBinary(pid uint32) (string, bool) {
	e.pidMu.Lock()
	if elem, ok := e.pidCache[pid]; ok {
		entry := elem.Value.(pidEntry)
		if time.Now().Before(entry.expires) {
			e.pidOrder.MoveToFront(elem)
			e.pidMu.Unlock()
			return entry.binary, entry.binary != ""
		}
		e.pidOrder.Remove(elem)
		delete(e.pidCache, pid)
	}
	e.pidMu.Unlock()

	path := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(path)
	resolved := err == nil && target != ""

	e.pidMu.Lock()
	defer e.pidMu.Unlock()
	e.evictPIDIfNeeded()
	entry := pidEntry{binary: target, expires: time.Now().Add(pidCacheTTL)}
	elem := e.pidOrder.PushFront(entry)
	e.pidCache[pid] = elem
	return target, resolved
}

func (e *Enricher) evictPIDIfNeeded() {
	for e.pidOrder.Len() >= pidCacheMaxSize {
		back := e.pidOrder.Back()
		if back == nil {
			break
		}
		for pid, elem := range e.pidCache {
			if elem == back {
				delete(e.pidCache, pid)
				break
			}
		}
		e.pidOrder.Remove(back)
	}
}

func (e *Enricher) resolveUser(uid uint32) string {
	e.userMu.RLock()
	if time.Since(e.lastUserLoad) > userCacheRefresh {
		e.userMu.RUnlock()
		e.loadUsers()
	} else {
		name, ok := e.userCache[uid]
		e.userMu.RUnlock()
		if ok {
			return name
		}
		return fmt.Sprintf("uid:%d", uid)
	}

	e.userMu.RLock()
	defer e.userMu.RUnlock()
	if name, ok := e.userCache[uid]; ok {
		return name
	}
	return fmt.Sprintf("uid:%d", uid)
}

func (e *Enricher) resolveContainer(pid uint32, cgroupID uint64) string {
	if cgroupID == 0 || cgroupID == 1 {
		return ""
	}

	e.cgroupMu.Lock()
	if entry, ok := e.cgroupCache[cgroupID]; ok && time.Now().Before(entry.expires) {
		e.cgroupMu.Unlock()
		return entry.name
	}
	e.cgroupMu.Unlock()

	name := e.lookupCgroupName(pid, cgroupID)

	e.cgroupMu.Lock()
	defer e.cgroupMu.Unlock()
	if len(e.cgroupCache) >= cgroupCacheMax {
		e.cgroupCache = make(map[uint64]cgroupEntry)
	}
	e.cgroupCache[cgroupID] = cgroupEntry{name: name, expires: time.Now().Add(cgroupCacheTTL)}
	return name
}

func (e *Enricher) lookupCgroupName(pid uint32, cgroupID uint64) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return fmt.Sprintf("cgroup:%d", cgroupID)
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}
		path := strings.TrimSpace(parts[2])
		if path == "" || path == "/" {
			continue
		}
		segments := strings.Split(strings.Trim(path, "/"), "/")
		last := segments[len(segments)-1]
		if last == "" {
			continue
		}
		if strings.HasPrefix(last, "docker-") && strings.HasSuffix(last, ".scope") {
			id := strings.TrimSuffix(strings.TrimPrefix(last, "docker-"), ".scope")
			if len(id) > 12 {
				id = id[:12]
			}
			return id
		}
		if len(last) > 64 {
			last = last[:64]
		}
		return last
	}

	return fmt.Sprintf("cgroup:%d", cgroupID)
}

func (e *Enricher) loadUsers() {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return
	}
	updated := make(map[uint32]string)
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 4)
		if len(parts) < 3 {
			continue
		}
		var uid uint32
		if _, err := fmt.Sscanf(parts[2], "%d", &uid); err == nil {
			updated[uid] = parts[0]
		}
	}
	e.userMu.Lock()
	defer e.userMu.Unlock()
	e.userCache = updated
	e.lastUserLoad = time.Now()
}
