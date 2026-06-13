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
	"ebpf-agent/internal/ringbuf"
)

const (
	chainMaxSteps   = 16
	chainWindow     = 5 * time.Minute
	chainMaxParents = 256
)

// ChainSpanEmitter emits correlated parent/child spans for kill-chain detection.
type ChainSpanEmitter interface {
	EmitChainSpan(ctx context.Context, parent trace.SpanContext, name string, attrs []attribute.KeyValue)
}

// ChainDetector correlates events along process lineage (ppid chains).
type ChainDetector struct {
	mu      sync.Mutex
	byPPID  map[uint32][]chainStep
	emitter ChainSpanEmitter
}

type chainStep struct {
	at        time.Time
	pid       uint32
	ppid      uint32
	eventType uint8
	binary    string
	technique string
}

func NewChainDetector(emitter ChainSpanEmitter) *ChainDetector {
	return &ChainDetector{
		byPPID:  make(map[uint32][]chainStep),
		emitter: emitter,
	}
}

// Observe records an enriched event for temporal kill-chain correlation.
func (c *ChainDetector) Observe(ctx context.Context, ev *enricher.EnrichedEvent) {
	if c == nil || ev == nil || ev.Raw == nil {
		return
	}
	if ev.Raw.EventType == ringbuf.EventFork || ev.Raw.EventType == ringbuf.EventExit {
		return
	}

	mapping := Map(ev)
	if len(mapping.Techniques) == 0 {
		return
	}
	tech := mapping.Techniques[0].ID

	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	step := chainStep{
		at:        now,
		pid:       ev.Raw.PID,
		ppid:      ev.Raw.PPID,
		eventType: ev.Raw.EventType,
		binary:    ev.Binary,
		technique: tech,
	}

	parentKey := ev.Raw.PPID
	if parentKey == 0 {
		parentKey = ev.Raw.PID
	}
	steps := append(c.byPPID[parentKey], step)
	if len(steps) > chainMaxSteps {
		steps = steps[len(steps)-chainMaxSteps:]
	}
	c.byPPID[parentKey] = steps

	c.pruneLocked(now)
	c.detectLocked(ctx, parentKey, steps)
}

func (c *ChainDetector) pruneLocked(now time.Time) {
	for k, steps := range c.byPPID {
		var kept []chainStep
		for _, s := range steps {
			if now.Sub(s.at) <= chainWindow {
				kept = append(kept, s)
			}
		}
		if len(kept) == 0 {
			delete(c.byPPID, k)
		} else {
			c.byPPID[k] = kept
		}
	}
	if len(c.byPPID) > chainMaxParents {
		c.byPPID = make(map[uint32][]chainStep)
	}
}

func (c *ChainDetector) detectLocked(ctx context.Context, ppid uint32, steps []chainStep) {
	if len(steps) < 3 || c.emitter == nil {
		return
	}

	hasExec := false
	hasConnect := false
	hasPriv := false
	var names []string
	for _, s := range steps {
		names = append(names, fmt.Sprintf("%s:%s", eventName(s.eventType), s.technique))
		switch s.eventType {
		case ringbuf.EventExec:
			hasExec = true
		case ringbuf.EventConnect:
			hasConnect = true
		case ringbuf.EventSetuid, ringbuf.EventSetgid, ringbuf.EventCapset:
			hasPriv = true
		}
	}

	// Simple kill-chain: shell execution -> privilege change -> outbound connect.
	if !(hasExec && hasConnect) && !(hasExec && hasPriv && hasConnect) {
		return
	}

	attrs := []attribute.KeyValue{
		attribute.Int64("ebpf.chain.ppid", int64(ppid)),
		attribute.String("ebpf.chain.steps", strings.Join(names, " -> ")),
		attribute.String("mitre.technique.ids", "T1059,T1071"),
	}
	c.emitter.EmitChainSpan(ctx, trace.SpanContext{}, "mitre.kill_chain", attrs)
}

func eventName(t uint8) string {
	switch t {
	case ringbuf.EventExec:
		return "exec"
	case ringbuf.EventConnect:
		return "connect"
	case ringbuf.EventOpenat:
		return "openat"
	default:
		return fmt.Sprintf("evt%d", t)
	}
}
