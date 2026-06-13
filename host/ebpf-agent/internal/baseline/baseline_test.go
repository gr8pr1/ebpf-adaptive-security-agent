package baseline

import (
	"testing"
	"time"

	"ebpf-agent/internal/aggregator"
)

func TestEWMAUpdatesOnIngest(t *testing.T) {
	eng := NewEngine(0.5, 2)
	w := &aggregator.Window{
		Start: time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 10, 14, 1, 0, 0, time.UTC),
		Counts: map[aggregator.DimensionKey]float64{
			{MetricName: "exec"}: 10,
		},
	}
	eng.Ingest(w)

	w2 := &aggregator.Window{
		Start: time.Date(2026, 6, 10, 14, 1, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 10, 14, 2, 0, 0, time.UTC),
		Counts: map[aggregator.DimensionKey]float64{
			{MetricName: "exec"}: 20,
		},
	}
	eng.Ingest(w2)

	mean, _, ewma, _, _, ready := eng.Lookup(aggregator.DimensionKey{MetricName: "exec"}, 14, int(time.Tuesday))
	if !ready {
		t.Fatal("expected bucket ready")
	}
	if ewma != 15 {
		t.Fatalf("expected EWMA 15, got %f", ewma)
	}
	if mean != 15 {
		t.Fatalf("expected EWMA mean 15, got %f", mean)
	}
}

func TestIngestFilteredSkipsKeys(t *testing.T) {
	eng := NewEngine(0.01, 1)
	w := &aggregator.Window{
		Start: time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 10, 14, 1, 0, 0, time.UTC),
		Counts: map[aggregator.DimensionKey]float64{
			{MetricName: "exec"}:    1,
			{MetricName: "ptrace"}: 1,
		},
	}
	skip := map[aggregator.DimensionKey]struct{}{
		{MetricName: "ptrace"}: {},
	}
	eng.IngestFiltered(w, skip)

	if eng.TotalSamples(aggregator.DimensionKey{MetricName: "exec"}) == 0 {
		t.Fatal("exec should be ingested")
	}
	if eng.TotalSamples(aggregator.DimensionKey{MetricName: "ptrace"}) != 0 {
		t.Fatal("ptrace should be skipped")
	}
}

func TestNeighborBucketFallback(t *testing.T) {
	eng := NewEngine(0.01, 2)
	key := aggregator.DimensionKey{MetricName: "dns"}

	// Populate Tuesday hour 13 (neighbor of hour 14) but not hour 14.
	tuesday := time.Date(2026, 6, 9, 13, 0, 0, 0, time.UTC) // 2026-06-09 is Tuesday
	w13 := &aggregator.Window{
		Start: tuesday,
		End:   tuesday.Add(time.Minute),
		Counts: map[aggregator.DimensionKey]float64{key: 4},
	}
	eng.Ingest(w13)
	eng.Ingest(w13)

	mean, _, _, _, _, ready := eng.Lookup(key, 14, int(time.Tuesday))
	if !ready {
		t.Fatal("expected neighbor fallback to make bucket ready")
	}
	if mean != 4 {
		t.Fatalf("expected neighbor mean 4, got %f", mean)
	}
}

func TestRestoreBackfillsEWMAFromLegacySnapshot(t *testing.T) {
	eng := NewEngine(0.01, 2)
	key := aggregator.DimensionKey{MetricName: "exec"}
	idx := SeasonalIndex(14, int(time.Tuesday))

	eng.mu.Lock()
	bl := &DimensionBaseline{}
	bl.Buckets[idx] = BucketStats{Count: 3, Sum: 9, SumSq: 27}
	eng.baselines[key] = bl
	eng.mu.Unlock()

	snaps := eng.Snapshot()
	eng2 := NewEngine(0.01, 2)
	eng2.Restore(snaps)

	mean, _, ewma, _, _, ready := eng2.Lookup(key, 14, int(time.Tuesday))
	if !ready {
		t.Fatal("expected legacy snapshot to be ready after EWMA backfill")
	}
	if mean != 3 || ewma != 3 {
		t.Fatalf("expected backfilled mean/ewma 3, got mean=%f ewma=%f", mean, ewma)
	}
}

func TestEWMAInitPersistsInJSON(t *testing.T) {
	eng := NewEngine(0.01, 1)
	w := &aggregator.Window{
		Start: time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 10, 14, 1, 0, 0, time.UTC),
		Counts: map[aggregator.DimensionKey]float64{
			{MetricName: "exec"}: 3,
		},
	}
	eng.Ingest(w)

	snaps := eng.Snapshot()
	eng2 := NewEngine(0.01, 1)
	eng2.Restore(snaps)

	_, _, ewma, _, _, ready := eng2.Lookup(aggregator.DimensionKey{MetricName: "exec"}, 14, int(time.Tuesday))
	if !ready || ewma != 3 {
		t.Fatalf("expected restored EWMA 3, got ewma=%f ready=%v", ewma, ready)
	}
}
