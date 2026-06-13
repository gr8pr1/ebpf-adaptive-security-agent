package scorer

import (
	"testing"
	"time"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
)

func TestCeilingTriggersAnomaly(t *testing.T) {
	eng := baseline.NewEngine(0.01, 2)
	w0 := &aggregator.Window{
		Start: time.Now(),
		End:   time.Now().Add(time.Minute),
		Counts: map[aggregator.DimensionKey]float64{
			{MetricName: "ptrace"}: 1,
		},
	}
	eng.Ingest(w0)
	eng.Ingest(w0)

	s := New(eng, 3.0, 1.0, "warning", map[string]float64{"ptrace": 5}, false, 0, nil)

	w := &aggregator.Window{
		Start: time.Now(),
		End:   time.Now().Add(time.Minute),
		Counts: map[aggregator.DimensionKey]float64{
			{MetricName: "ptrace"}: 10,
		},
	}
	res := s.Score(w)
	if len(res) != 1 || !res[0].Anomaly || res[0].Severity != "info" {
		t.Fatalf("expected ceiling anomaly info (low confidence), got %+v", res)
	}
}

func TestCeilingMultiplierWithoutStaticCeiling(t *testing.T) {
	eng := baseline.NewEngine(0.01, 2)
	base := time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC)
	key := aggregator.DimensionKey{MetricName: "exec"}
	for i := 0; i < 3; i++ {
		eng.Ingest(&aggregator.Window{
			Start:  base.Add(time.Duration(i) * time.Minute),
			End:    base.Add(time.Duration(i+1) * time.Minute),
			Counts: map[aggregator.DimensionKey]float64{key: 2},
		})
	}

	s := New(eng, 3.0, 1.0, "warning", map[string]float64{}, false, 3.0, nil)
	res := s.Score(&aggregator.Window{
		Start:  base.Add(10 * time.Minute),
		End:    base.Add(11 * time.Minute),
		Counts: map[aggregator.DimensionKey]float64{key: 20},
	})
	if len(res) != 1 || !res[0].Anomaly {
		t.Fatalf("expected multiplier ceiling anomaly, got %+v", res)
	}
}
