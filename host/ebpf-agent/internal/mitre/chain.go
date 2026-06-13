package mitre

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/proctable"
	"ebpf-agent/internal/ringbuf"
)

const chainWindow = 5 * time.Minute

// ChainSpanEmitter emits correlated parent/child spans for kill-chain detection.
type ChainSpanEmitter interface {
	EmitChainSpan(ctx context.Context, parent trace.SpanContext, name string, attrs []attribute.KeyValue)
}

// ChainDetector correlates events along process lineage with temporal ordering.
type ChainDetector struct {
	mu        sync.Mutex
	emitter   ChainSpanEmitter
	table     *proctable.Table
	roots     map[string]struct{}
	steps     map[uint32][]chainStep
	emitted   map[string]time.Time
}

type chainStep struct {
	at        time.Time
	pid       uint32
	eventType uint8
	binary    string
	technique string
}

func NewChainDetector(emitter ChainSpanEmitter, table *proctable.Table, supervisorRoots []string) *ChainDetector {
	roots := map[string]struct{}{
		"systemd": {}, "init": {}, "dockerd": {}, "containerd": {}, "kubelet": {}, "runc": {},
	}
	for _, r := range supervisorRoots {
		roots[strings.ToLower(r)] = struct{}{}
	}
	return &ChainDetector{
		emitter: emitter,
		table:   table,
		roots:   roots,
		steps:   make(map[uint32][]chainStep),
		emitted: make(map[string]time.Time),
	}
}

func (c *ChainDetector) Observe(ctx context.Context, ev *enricher.EnrichedEvent) {
	if c == nil || ev == nil || ev.Raw == nil || c.emitter == nil {
		return
	}
	if c.table != nil {
		c.table.Observe(ev)
	}

	raw := ev.Raw
	if raw.EventType == ringbuf.EventFork || raw.EventType == ringbuf.EventExit {
		return
	}

	mapping := Map(ev)
	if len(mapping.Techniques) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	step := chainStep{
		at:        now,
		pid:       raw.PID,
		eventType: raw.EventType,
		binary:    ev.Binary,
		technique: mapping.Techniques[0].ID,
	}
	steps := append(c.steps[raw.PID], step)
	if len(steps) > 16 {
		steps = steps[len(steps)-16:]
	}
	c.steps[raw.PID] = steps
	c.pruneLocked(now)
	c.detectLocked(ctx, raw.PID, steps)
}

func (c *ChainDetector) pruneLocked(now time.Time) {
	for pid, steps := range c.steps {
		var kept []chainStep
		for _, s := range steps {
			if now.Sub(s.at) <= chainWindow {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			delete(c.steps, pid)
		} else {
			c.steps[pid] = kept
		}
	}
	for k, t := range c.emitted {
		if now.Sub(t) > chainWindow {
			delete(c.emitted, k)
		}
	}
}

func (c *ChainDetector) detectLocked(ctx context.Context, pid uint32, steps []chainStep) {
	if len(steps) < 2 {
		return
	}
	if c.isSupervisorRoot(pid) {
		return
	}

	var execAt, connectAt time.Time
	var execTech, connectTech string
	var hasPriv bool
	for _, s := range steps {
		switch s.eventType {
		case ringbuf.EventExec:
			if execAt.IsZero() {
				execAt = s.at
				execTech = s.technique
			}
		case ringbuf.EventConnect:
			connectAt = s.at
			connectTech = s.technique
		case ringbuf.EventSetuid, ringbuf.EventSetgid, ringbuf.EventCapset:
			hasPriv = true
		}
	}
	if execAt.IsZero() || connectAt.IsZero() || !connectAt.After(execAt) {
		return
	}
	if hasPriv && connectAt.Before(execAt) {
		return
	}

	key := fmt.Sprintf("%d:%d:%d", pid, execAt.Unix(), connectAt.Unix())
	if _, ok := c.emitted[key]; ok {
		return
	}
	c.emitted[key] = time.Now()

	techs := []string{execTech, connectTech}
	if hasPriv {
		techs = append(techs, "T1548.001")
	}
	names := make([]string, 0, len(steps))
	for _, s := range steps {
		names = append(names, fmt.Sprintf("%s:%s", eventName(s.eventType), s.technique))
	}

	attrs := []attribute.KeyValue{
		attribute.Int64("ebpf.chain.pid", int64(pid)),
		attribute.String("ebpf.chain.steps", strings.Join(names, " -> ")),
		attribute.String("mitre.technique.ids", strings.Join(uniqueStrings(techs), ",")),
	}
	c.emitter.EmitChainSpan(ctx, trace.SpanContext{}, "mitre.kill_chain", attrs)
}

func (c *ChainDetector) isSupervisorRoot(pid uint32) bool {
	if pid <= 1 {
		return true
	}
	if c.table == nil {
		return false
	}
	entry, ok := c.table.EntryFor(pid)
	if !ok {
		return false
	}
	comm := strings.ToLower(entry.Comm)
	base := strings.ToLower(strings.TrimPrefix(entry.Binary, "/usr/bin/"))
	base = strings.TrimPrefix(base, "/bin/")
	if _, ok := c.roots[comm]; ok {
		return true
	}
	if _, ok := c.roots[base]; ok {
		return true
	}
	return false
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, s := range in {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func eventName(t uint8) string {
	switch t {
	case ringbuf.EventExec:
		return "exec"
	case ringbuf.EventConnect:
		return "connect"
	case ringbuf.EventOpenat:
		return "openat"
	case ringbuf.EventSetuid, ringbuf.EventSetgid:
		return "priv"
	case ringbuf.EventCapset:
		return "capset"
	default:
		return fmt.Sprintf("evt%d", t)
	}
}
