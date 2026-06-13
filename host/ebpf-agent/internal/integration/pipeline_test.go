//go:build integration

package integration_test

import (
	"testing"
	"time"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
	"ebpf-agent/internal/otelexport"
	"ebpf-agent/internal/phase"
	"ebpf-agent/internal/ringbuf"
	"ebpf-agent/internal/scorer"
)

// replayHarness wires baseline -> phase -> scorer for synthetic window replay.
type replayHarness struct {
	engine *baseline.Engine
	phase  *phase.Manager
	last   *[]scorer.Result
}

func newHarness(t *testing.T, minSamples int, ceilings map[string]float64) *replayHarness {
	t.Helper()
	eng := baseline.NewEngine(0.01, minSamples)
	sc := scorer.New(eng, 3.0, 1.0, "warning", ceilings, false, 0, nil)
	var lastResults []scorer.Result
	mgr := phase.NewManager(eng, sc, nil, time.Hour, time.Hour, func(results []scorer.Result, w *aggregator.Window) {
		lastResults = append([]scorer.Result(nil), results...)
	})
	mgr.SetPhaseForTest(phase.PhaseMonitoring)
	return &replayHarness{engine: eng, phase: mgr, last: &lastResults}
}

func (h *replayHarness) ingestLearning(windows ...*aggregator.Window) {
	for _, w := range windows {
		h.engine.Ingest(w)
	}
}

func (h *replayHarness) replay(w *aggregator.Window) []scorer.Result {
	h.phase.ProcessWindow(w)
	return *h.last
}

func windowAt(t time.Time, counts map[aggregator.DimensionKey]float64) *aggregator.Window {
	return &aggregator.Window{
		Start:  t,
		End:    t.Add(time.Minute),
		Counts: counts,
	}
}

func hasAnomaly(results []scorer.Result, metric string, coldStart bool) bool {
	for _, r := range results {
		if r.Key.MetricName != metric {
			continue
		}
		if coldStart {
			return r.ColdStart && r.Anomaly
		}
		return r.Anomaly && !r.ColdStart
	}
	return false
}

func TestReplayColdStartUnseenDimension(t *testing.T) {
	h := newHarness(t, 2, nil)
	w := windowAt(
		time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC),
		map[aggregator.DimensionKey]float64{
			{MetricName: "connect", User: "alice"}: 5,
		},
	)
	results := h.replay(w)

	if !hasAnomaly(results, "connect", true) {
		t.Fatal("expected cold-start anomaly for unseen connect dimension")
	}
	if h.engine.TotalSamples(aggregator.DimensionKey{MetricName: "connect", User: "alice"}) == 0 {
		t.Fatal("cold-start dimension should be ingested during fast-track learning")
	}
}

func TestReplayZScoreBurstAfterLearning(t *testing.T) {
	h := newHarness(t, 2, nil)
	base := time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC)
	key := aggregator.DimensionKey{MetricName: "exec"}

	for i := 0; i < 5; i++ {
		h.ingestLearning(windowAt(base.Add(time.Duration(i)*time.Minute), map[aggregator.DimensionKey]float64{key: 2}))
	}

	results := h.replay(windowAt(base.Add(10*time.Minute), map[aggregator.DimensionKey]float64{key: 100}))
	if !hasAnomaly(results, "exec", false) {
		t.Fatal("expected z-score anomaly after sustained baseline and burst")
	}
	if h.engine.TotalSamples(key) < 5 {
		t.Fatal("expected at least 5 ingested learning windows before burst")
	}
}

func TestReplayCeilingAnomalySkipsIngest(t *testing.T) {
	h := newHarness(t, 2, map[string]float64{"ptrace": 5})
	base := time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC)
	execKey := aggregator.DimensionKey{MetricName: "exec"}
	ptraceKey := aggregator.DimensionKey{MetricName: "ptrace"}

	h.ingestLearning(windowAt(base, map[aggregator.DimensionKey]float64{execKey: 2}))
	h.ingestLearning(windowAt(base.Add(time.Minute), map[aggregator.DimensionKey]float64{execKey: 2}))

	results := h.replay(windowAt(base.Add(2*time.Minute), map[aggregator.DimensionKey]float64{
		execKey:   2,
		ptraceKey: 10,
	}))

	if !hasAnomaly(results, "ptrace", false) {
		t.Fatal("expected ceiling anomaly for ptrace")
	}
	if h.engine.TotalSamples(ptraceKey) != 0 {
		t.Fatal("ceiling anomaly should not poison baseline")
	}
	if h.engine.TotalSamples(execKey) == 0 {
		t.Fatal("benign exec dimension should still be ingested")
	}
}

func TestReplayBenignWindowNoAnomaly(t *testing.T) {
	h := newHarness(t, 2, nil)
	base := time.Date(2026, 6, 10, 14, 0, 0, 0, time.UTC)
	key := aggregator.DimensionKey{MetricName: "dns"}

	for i := 0; i < 4; i++ {
		h.ingestLearning(windowAt(base.Add(time.Duration(i)*time.Minute), map[aggregator.DimensionKey]float64{key: 3}))
	}

	results := h.replay(windowAt(base.Add(5*time.Minute), map[aggregator.DimensionKey]float64{key: 3}))
	for _, r := range results {
		if r.Key.MetricName == "dns" && r.Anomaly {
			t.Fatalf("expected no anomaly for stable dns traffic, got %+v", r)
		}
	}
}

func TestReplaySamplingKeyParity(t *testing.T) {
	sampling := map[string]float64{
		"suspicious_connect": 1.0,
		"sudo":               1.0,
		"sensitive_file":     1.0,
		"connect":            0.01,
		"exec":               0.01,
	}

	cases := []struct {
		name     string
		evType   uint8
		flags    uint8
		wantRate float64
	}{
		{"suspicious_connect", ringbuf.EventConnect, ringbuf.FlagSuspiciousPort, 1.0},
		{"plain_connect", ringbuf.EventConnect, 0, 0.01},
		{"sudo_exec", ringbuf.EventExec, ringbuf.FlagSudo, 1.0},
		{"sensitive_open", ringbuf.EventOpenat, ringbuf.FlagSensitiveFile, 1.0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rate := otelexport.SampleRate(sampling, tc.evType, tc.flags)
			if rate != tc.wantRate {
				t.Fatalf("rate = %v, want %v", rate, tc.wantRate)
			}
		})
	}
}
