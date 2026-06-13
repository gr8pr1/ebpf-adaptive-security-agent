package composite

import (
	"log"
	"sync"
	"time"

	"ebpf-agent/internal/config"
	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/proctable"
	"ebpf-agent/internal/ringbuf"
)

// Match is a fired composite correlation rule.
type Match struct {
	RuleName string
	Severity string
	PID      uint32
	Steps    string
}

type stepRecord struct {
	at        time.Time
	eventType uint8
	binary    string
}

// Engine evaluates explainable multi-step rules per process.
type Engine struct {
	rules []compiled
	steps map[uint32][]stepRecord
	mu    sync.Mutex
}

type compiled struct {
	name     string
	severity string
	window   time.Duration
	sequence []uint8
}

func New(cfg []config.CompositeRuleConfig) *Engine {
	e := &Engine{steps: make(map[uint32][]stepRecord)}
	for _, r := range cfg {
		c := compiled{
			name:     r.Name,
			severity: r.Severity,
			window:   r.Window,
		}
		if c.severity == "" {
			c.severity = "warning"
		}
		if c.window <= 0 {
			c.window = 30 * time.Second
		}
		for _, s := range r.Sequence {
			if id, ok := parseStep(s); ok {
				c.sequence = append(c.sequence, id)
			}
		}
		if len(c.sequence) >= 2 {
			e.rules = append(e.rules, c)
		}
	}
	return e
}

func DefaultRules() []config.CompositeRuleConfig {
	return []config.CompositeRuleConfig{
		{
			Name:     "shell_exec_then_connect",
			Sequence: []string{"exec", "connect"},
			Window:   30 * time.Second,
			Severity: "warning",
		},
	}
}

func (e *Engine) Observe(ev *enricher.EnrichedEvent) []Match {
	if e == nil || ev == nil || ev.Raw == nil {
		return nil
	}
	raw := ev.Raw
	if raw.EventType != ringbuf.EventExec && raw.EventType != ringbuf.EventConnect &&
		raw.EventType != ringbuf.EventSetuid && raw.EventType != ringbuf.EventSetgid {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	pid := raw.PID
	steps := append(e.steps[pid], stepRecord{at: now, eventType: raw.EventType, binary: ev.Binary})
	var kept []stepRecord
	for _, s := range steps {
		if now.Sub(s.at) <= 60*time.Second {
			kept = append(kept, s)
		}
	}
	e.steps[pid] = kept

	var out []Match
	for _, rule := range e.rules {
		if m, ok := e.matchRule(rule, kept); ok {
			out = append(out, m)
		}
	}
	return out
}

func (e *Engine) matchRule(rule compiled, steps []stepRecord) (Match, bool) {
	if len(rule.sequence) < 2 {
		return Match{}, false
	}
	seqIdx := 0
	var first time.Time
	var names []string
	for _, s := range steps {
		want := rule.sequence[seqIdx]
		if s.eventType != want {
			continue
		}
		if seqIdx == 0 {
			first = s.at
			names = []string{eventName(s.eventType)}
			seqIdx = 1
		} else {
			if s.at.Sub(first) > rule.window {
				seqIdx = 0
				first = time.Time{}
				names = nil
				if s.eventType == rule.sequence[0] {
					first = s.at
					names = []string{eventName(s.eventType)}
					seqIdx = 1
				} else {
					continue
				}
			} else {
				names = append(names, eventName(s.eventType))
				seqIdx++
			}
		}
		if seqIdx == len(rule.sequence) {
			return Match{
				RuleName: rule.name,
				Severity: rule.severity,
				Steps:    joinSteps(names),
			}, true
		}
	}
	return Match{}, false
}

func EmitLogs(matches []Match, pid uint32) {
	for _, m := range matches {
		log.Printf("COMPOSITE [%s] %s pid=%d steps=%s", m.Severity, m.RuleName, pid, m.Steps)
	}
}

func parseStep(s string) (uint8, bool) {
	switch s {
	case "exec":
		return ringbuf.EventExec, true
	case "connect":
		return ringbuf.EventConnect, true
	case "setuid", "priv":
		return ringbuf.EventSetuid, true
	default:
		return 0, false
	}
}

func eventName(t uint8) string {
	switch t {
	case ringbuf.EventExec:
		return "exec"
	case ringbuf.EventConnect:
		return "connect"
	case ringbuf.EventSetuid:
		return "setuid"
	default:
		return "step"
	}
}

func joinSteps(parts []string) string {
	if len(parts) == 0 {
		return ""
	}
	s := parts[0]
	for i := 1; i < len(parts); i++ {
		s += " -> " + parts[i]
	}
	return s
}

// ObserveProcessTable is optional hook when proctable is wired separately.
func ObserveProcessTable(_ *proctable.Table, _ *enricher.EnrichedEvent) {}
