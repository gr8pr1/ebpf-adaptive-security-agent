package novelty

import (
	"fmt"
	"log"
	"sync"
	"time"

	"ebpf-agent/internal/dimkey"
	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/phase"
	"ebpf-agent/internal/ringbuf"
	"ebpf-agent/internal/store"
)

// Signal is a first-seen tuple novelty alert.
type Signal struct {
	Kind     string
	Key      string
	Severity string
	Event    *enricher.EnrichedEvent
}

// Tracker records persistent first-seen (process, dest_ip, port) tuples.
type Tracker struct {
	store    *store.Store
	phaseFn  func() int
	mu       sync.Mutex
	memSeen  map[string]struct{}
	interval map[string][]time.Time // beacon detection: key -> connect times
}

func New(st *store.Store, phaseFn func() int) *Tracker {
	return &Tracker{
		store:    st,
		phaseFn:  phaseFn,
		memSeen:  make(map[string]struct{}),
		interval: make(map[string][]time.Time),
	}
}

func (t *Tracker) Observe(ev *enricher.EnrichedEvent) []Signal {
	if t == nil || ev == nil || ev.Raw == nil {
		return nil
	}
	if t.phaseFn != nil && t.phaseFn() != phase.PhaseMonitoring {
		return nil
	}

	var out []Signal
	raw := ev.Raw

	if raw.EventType == ringbuf.EventConnect && raw.IPVersion != ringbuf.IPVersionNone {
		proc := processKey(ev)
		ip := raw.FormatDestIP()
		port := raw.DestPort
		key := fmt.Sprintf("connect:%s:%s:%d", proc, ip, port)
		if t.markSeen(key) {
			out = append(out, Signal{
				Kind: "first_seen_connect", Key: key, Severity: "warning", Event: ev,
			})
		}
		if beacon := t.checkBeacon(key); beacon {
			out = append(out, Signal{
				Kind: "beacon_connect", Key: key, Severity: "info", Event: ev,
			})
		}
	}

	return out
}

func processKey(ev *enricher.EnrichedEvent) string {
	label := dimkey.ProcessLabel(ev.Binary, ev.Raw.CommString(), false)
	if label != "" {
		return label
	}
	return "host"
}

func (t *Tracker) markSeen(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.memSeen[key]; ok {
		return false
	}
	if t.store != nil {
		if t.store.HasNovelty(key) {
			return false
		}
		_ = t.store.RecordNovelty(key)
	}
	t.memSeen[key] = struct{}{}
	return true
}

func (t *Tracker) checkBeacon(key string) bool {
	now := time.Now()
	t.mu.Lock()
	defer t.mu.Unlock()
	times := append(t.interval[key], now)
	if len(times) > 8 {
		times = times[len(times)-8:]
	}
	t.interval[key] = times
	if len(times) < 4 {
		return false
	}
	var gaps []time.Duration
	for i := 1; i < len(times); i++ {
		gaps = append(gaps, times[i].Sub(times[i-1]))
	}
	if len(gaps) < 3 {
		return false
	}
	base := gaps[0]
	if base < 2*time.Second || base > 10*time.Minute {
		return false
	}
	for _, g := range gaps[1:] {
		diff := g - base
		if diff < 0 {
			diff = -diff
		}
		if diff > base/5 {
			return false
		}
	}
	return true
}

func EmitLogs(signals []Signal) {
	for _, s := range signals {
		ev := s.Event
		log.Printf("NOVELTY [%s] %s key=%s pid=%d comm=%s dest=%s:%d",
			s.Severity, s.Kind, s.Key, ev.Raw.PID, ev.Raw.CommString(),
			ev.Raw.FormatDestIP(), ev.Raw.DestPort)
	}
}
