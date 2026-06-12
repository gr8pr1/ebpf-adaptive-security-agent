package mitre

import (
	"testing"

	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/ringbuf"
)

func TestForkExitUntagged(t *testing.T) {
	for _, evType := range []uint8{ringbuf.EventFork, ringbuf.EventExit} {
		ev := &enricher.EnrichedEvent{Raw: &ringbuf.Event{EventType: evType}}
		m := Map(ev)
		if len(m.Techniques) != 0 {
			t.Fatalf("event type %d should not map to MITRE tags, got %+v", evType, m.Techniques)
		}
	}
}

func TestSuspiciousConnectTagged(t *testing.T) {
	ev := &enricher.EnrichedEvent{
		Raw: &ringbuf.Event{
			EventType: ringbuf.EventConnect,
			Flags:     ringbuf.FlagSuspiciousPort,
			DestPort:  4444,
		},
	}
	m := Map(ev)
	found := false
	for _, tech := range m.Techniques {
		if tech.ID == "T1571" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected T1571 for suspicious connect, got %+v", m.Techniques)
	}
}
