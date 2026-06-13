package aggregator

import (
	"testing"
	"time"

	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/ringbuf"
)

func TestUniqueDestIPsMetric(t *testing.T) {
	a := New(time.Minute, true, true, false, true, true, true, true, true)
	ev := &enricher.EnrichedEvent{
		Raw: &ringbuf.Event{
			EventType: ringbuf.EventConnect,
			IPVersion: ringbuf.IPVersion4,
			DestIP:    [16]byte{10, 0, 0, 1},
		},
		Username: "u1",
		Resolved: true,
		Binary:   "/usr/bin/curl",
	}
	a.Add(ev)
	a.Add(ev) // same IP — should not double-count unique_dest_ips
	w := a.Rotate()
	var u float64
	for k, v := range w.Counts {
		if k.MetricName == "unique_dest_ips" && k.User == "u1" {
			u = v
			break
		}
	}
	if u != 1 {
		t.Fatalf("expected 1 unique IP for user, got %v", w.Counts)
	}
}
