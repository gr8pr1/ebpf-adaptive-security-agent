package composite

import (
	"testing"
	"time"

	"ebpf-agent/internal/config"
	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/ringbuf"
)

func TestExecConnectWithinWindow(t *testing.T) {
	e := New([]config.CompositeRuleConfig{
		{Name: "exec_connect", Sequence: []string{"exec", "connect"}, Window: 30 * time.Second, Severity: "warning"},
	})
	now := time.Now()
	evConn := &enricher.EnrichedEvent{Raw: &ringbuf.Event{PID: 42, EventType: ringbuf.EventConnect}}

	e.steps[42] = []stepRecord{{at: now.Add(-5 * time.Second), eventType: ringbuf.EventExec}}
	matches := e.Observe(evConn)
	if len(matches) != 1 || matches[0].RuleName != "exec_connect" {
		t.Fatalf("expected exec->connect match, got %+v", matches)
	}
}

func TestConnectAfterWindowDoesNotFalsePositive(t *testing.T) {
	e := New(DefaultRules())
	now := time.Now()
	pid := uint32(99)
	e.steps[pid] = []stepRecord{{at: now.Add(-60 * time.Second), eventType: ringbuf.EventExec}}
	evConn := &enricher.EnrichedEvent{Raw: &ringbuf.Event{PID: pid, EventType: ringbuf.EventConnect}}
	if matches := e.Observe(evConn); len(matches) != 0 {
		t.Fatalf("expected no match after window expiry, got %+v", matches)
	}
}
