package phase

import (
	"log"
	"strconv"
	"sync"
	"time"

	"ebpf-agent/internal/aggregator"
	"ebpf-agent/internal/baseline"
	"ebpf-agent/internal/scorer"
	"ebpf-agent/internal/store"
)

const metaLearningStartedAt = "learning_started_at"

const (
	PhaseLearning   = 1
	PhaseMonitoring = 2
)

// Manager controls the learning-to-monitoring phase transition.
type Manager struct {
	engine    *baseline.Engine
	scorer    *scorer.Scorer
	store     *store.Store

	learningDuration time.Duration
	recalibInterval  time.Duration
	learningStart    time.Time
	lastRecalib      time.Time

	mu    sync.RWMutex
	phase int

	onScore func([]scorer.Result, *aggregator.Window)
}

func NewManager(
	engine *baseline.Engine,
	sc *scorer.Scorer,
	st *store.Store,
	learningDuration time.Duration,
	recalibInterval time.Duration,
	onScore func([]scorer.Result, *aggregator.Window),
) *Manager {
	m := &Manager{
		engine:           engine,
		scorer:           sc,
		store:            st,
		learningDuration: learningDuration,
		recalibInterval:  recalibInterval,
		learningStart:    time.Now(),
		lastRecalib:      time.Now(),
		phase:            PhaseLearning,
		onScore:          onScore,
	}

	if st != nil {
		snaps, err := st.LoadBaseline()
		if err != nil {
			log.Printf("WARN: failed to load persisted baseline: %v", err)
			m.learningStart = time.Now()
			if err2 := st.SetMeta(metaLearningStartedAt, strconv.FormatInt(m.learningStart.Unix(), 10)); err2 != nil {
				log.Printf("WARN: failed to persist learning_started_at: %v", err2)
			}
		} else if len(snaps) > 0 {
			engine.Restore(snaps)
			phaseStr, _ := st.GetMeta("phase")
			if phaseStr == "monitoring" {
				m.phase = PhaseMonitoring
				log.Printf("Restored baseline with %d dimensions, entering monitoring phase", len(snaps))
			} else {
				log.Printf("Restored baseline with %d dimensions, continuing learning phase", len(snaps))
				if ts, err := st.GetMeta(metaLearningStartedAt); err == nil && ts != "" {
					if sec, err := strconv.ParseInt(ts, 10, 64); err == nil {
						m.learningStart = time.Unix(sec, 0)
					}
				} else {
					log.Printf("WARN: learning_started_at missing in state DB; learning timer reset to now (migration)")
					m.learningStart = time.Now()
					_ = st.SetMeta(metaLearningStartedAt, strconv.FormatInt(m.learningStart.Unix(), 10))
				}
			}
		} else {
			m.learningStart = time.Now()
			if err := st.SetMeta(metaLearningStartedAt, strconv.FormatInt(m.learningStart.Unix(), 10)); err != nil {
				log.Printf("WARN: failed to persist learning_started_at: %v", err)
			}
		}
	}

	return m
}

func (m *Manager) Phase() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.phase
}

// SetPhaseForTest forces the lifecycle phase (integration tests only).
func (m *Manager) SetPhaseForTest(p int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.phase = p
}

func (m *Manager) Progress() float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.phase == PhaseMonitoring {
		return 1.0
	}
	elapsed := time.Since(m.learningStart)
	p := elapsed.Seconds() / m.learningDuration.Seconds()
	if p > 1.0 {
		p = 1.0
	}
	return p
}

// ProcessWindow handles a completed aggregation window.
func (m *Manager) ProcessWindow(w *aggregator.Window) {
	m.mu.Lock()
	currentPhase := m.phase

	if currentPhase == PhaseLearning {
		if time.Since(m.learningStart) >= m.learningDuration {
			m.phase = PhaseMonitoring
			currentPhase = PhaseMonitoring
			log.Printf("Learning phase complete, transitioning to monitoring")
			m.persist("monitoring")
			m.lastRecalib = time.Now()
		}
	}
	m.mu.Unlock()

	if currentPhase == PhaseLearning {
		m.engine.Ingest(w)
		return
	}

	// Monitoring: score before ingest so cold-start and baseline stats are not poisoned.
	results := m.scorer.Score(w)
	if m.onScore != nil {
		m.onScore(results, w)
	}

	skip := make(map[aggregator.DimensionKey]struct{})
	for _, r := range results {
		if r.Anomaly {
			if r.ColdStart && m.engine.ShouldIngestColdStart(r.Key, w.Start) {
				continue
			}
			skip[r.Key] = struct{}{}
		}
	}
	m.engine.IngestFiltered(w, skip)

	m.mu.Lock()
	if time.Since(m.lastRecalib) >= m.recalibInterval {
		m.lastRecalib = time.Now()
		m.mu.Unlock()
		m.persist("monitoring")
		return
	}
	m.mu.Unlock()
}

// Reset re-enters the learning phase.
func (m *Manager) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.phase = PhaseLearning
	m.learningStart = time.Now()
	if m.store != nil {
		if err := m.store.SetMeta(metaLearningStartedAt, strconv.FormatInt(m.learningStart.Unix(), 10)); err != nil {
			log.Printf("WARN: failed to persist learning_started_at on reset: %v", err)
		}
	}
	log.Printf("Baseline reset, entering learning phase")
}

// Persist saves the current baseline and phase to the state store (e.g. on shutdown).
func (m *Manager) Persist() {
	m.mu.RLock()
	phaseName := "learning"
	if m.phase == PhaseMonitoring {
		phaseName = "monitoring"
	}
	m.mu.RUnlock()
	m.persist(phaseName)
}

func (m *Manager) persist(phaseName string) {
	if m.store == nil {
		return
	}
	snaps := m.engine.Snapshot()
	if err := m.store.SaveBaseline(snaps); err != nil {
		log.Printf("WARN: failed to persist baseline: %v", err)
		return
	}
	if err := m.store.SetMeta("phase", phaseName); err != nil {
		log.Printf("WARN: failed to persist phase: %v", err)
	}
}
