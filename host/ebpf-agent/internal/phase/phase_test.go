package phase

import (
	"testing"
	"time"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
	"ebpf-agent/internal/scorer"
)

func TestProcessWindowColdStartBeforeIngest(t *testing.T) {
	eng := baseline.NewEngine(0.01, 2)
	sc := scorer.New(eng, 3.0, 1.0, "warning", nil, false)

	var gotColdStart bool
	mgr := NewManager(eng, sc, nil, time.Hour, time.Hour, func(results []scorer.Result, w *aggregator.Window) {
		for _, r := range results {
			if r.ColdStart {
				gotColdStart = true
			}
		}
	})
	mgr.phase = PhaseMonitoring

	w := &aggregator.Window{
		Start: time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 10, 14, 1, 0, 0, time.UTC),
		Counts: map[aggregator.DimensionKey]float64{
			{MetricName: "connect", User: "alice"}: 5,
		},
	}

	mgr.ProcessWindow(w)

	if !gotColdStart {
		t.Fatal("expected cold-start anomaly for unseen dimension")
	}

	if eng.TotalSamples(aggregator.DimensionKey{MetricName: "connect", User: "alice"}) != 0 {
		t.Fatal("cold-start dimension should not be ingested when flagged anomalous")
	}
}

func TestProcessWindowIngestsNonAnomalousOnly(t *testing.T) {
	eng := baseline.NewEngine(0.01, 2)
	sc := scorer.New(eng, 3.0, 1.0, "warning", map[string]float64{"ptrace": 5}, false)

	mgr := NewManager(eng, sc, nil, time.Hour, time.Hour, nil)
	mgr.phase = PhaseMonitoring

	// Seed baseline for exec so it is known and below ceiling.
	seed := &aggregator.Window{
		Start: time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 10, 14, 1, 0, 0, time.UTC),
		Counts: map[aggregator.DimensionKey]float64{
			{MetricName: "exec"}: 2,
		},
	}
	eng.Ingest(seed)
	eng.Ingest(seed)

	w := &aggregator.Window{
		Start: time.Date(2026, 6, 10, 14, 2, 0, 0, time.UTC),
		End:   time.Date(2026, 6, 10, 14, 3, 0, 0, time.UTC),
		Counts: map[aggregator.DimensionKey]float64{
			{MetricName: "exec"}:    2,
			{MetricName: "ptrace"}: 10,
		},
	}

	mgr.ProcessWindow(w)

	if eng.TotalSamples(aggregator.DimensionKey{MetricName: "exec"}) == 0 {
		t.Fatal("expected non-anomalous exec dimension to be ingested")
	}
	if eng.TotalSamples(aggregator.DimensionKey{MetricName: "ptrace"}) != 0 {
		t.Fatal("expected anomalous ptrace dimension to be skipped")
	}
}
