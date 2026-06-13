package baseline

import (
	"testing"
	"time"

	"ebpf-agent/internal/aggregator"
)

func TestHeldFastTrackByMetricName(t *testing.T) {
	eng := NewEngine(0.01, 2)
	eng.SetFastTrackWindow(time.Hour)
	at := time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC)

	key := aggregator.DimensionKey{MetricName: "ptrace", User: "alice", Process: "bin:/usr/bin/strace"}
	eng.StartFastTrack(key, at)
	eng.MarkHighSeverityMetric("ptrace")

	if eng.ShouldIngestColdStart(key, at.Add(time.Minute)) {
		t.Fatal("high-severity metric should block fast-track ingest")
	}

	other := aggregator.DimensionKey{MetricName: "exec", User: "alice"}
	eng.StartFastTrack(other, at)
	if !eng.ShouldIngestColdStart(other, at.Add(time.Minute)) {
		t.Fatal("non-held metric should ingest during fast-track")
	}
}
