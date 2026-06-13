package rules

import (
	"log"
	"sync"

	"ebpf-agent/internal/config"
	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/ringbuf"
)

// Match describes a fired event-level rule (scorer-independent).
type Match struct {
	RuleName string
	Severity string
	Event    *enricher.EnrichedEvent
}

// Engine evaluates config-driven first-occurrence / flag rules per enriched event.
type Engine struct {
	rules []compiledRule
	once  sync.Map // ruleName -> seen
}

type compiledRule struct {
	name     string
	severity string
	once     bool
	types    map[uint8]struct{}
	flags    uint8 // 0 = any flags for type
}

func New(cfg []config.EventRuleConfig) *Engine {
	e := &Engine{}
	for _, r := range cfg {
		cr := compiledRule{
			name:     r.Name,
			severity: r.Severity,
			once:     r.Once,
			types:    make(map[uint8]struct{}),
		}
		if cr.severity == "" {
			cr.severity = "warning"
		}
		for _, t := range r.EventTypes {
			if id, ok := parseEventType(t); ok {
				cr.types[id] = struct{}{}
			}
		}
		for _, f := range r.Flags {
			cr.flags |= parseFlag(f)
		}
		if len(cr.types) > 0 {
			e.rules = append(e.rules, cr)
		}
	}
	return e
}

func DefaultRules() []config.EventRuleConfig {
	return []config.EventRuleConfig{
		{Name: "ptrace", EventTypes: []string{"ptrace"}, Severity: "critical", Once: false},
		{Name: "capset", EventTypes: []string{"capset"}, Severity: "warning", Once: false},
		{Name: "suspicious_connect", EventTypes: []string{"connect"}, Flags: []string{"suspicious_port"}, Severity: "warning", Once: false},
		{Name: "sensitive_file", EventTypes: []string{"openat"}, Flags: []string{"sensitive_file"}, Severity: "warning", Once: false},
		{Name: "setuid", EventTypes: []string{"setuid", "setgid"}, Severity: "warning", Once: false},
		{Name: "sudo", EventTypes: []string{"exec"}, Flags: []string{"sudo"}, Severity: "warning", Once: false},
	}
}

func (e *Engine) Evaluate(ev *enricher.EnrichedEvent) []Match {
	if e == nil || ev == nil || ev.Raw == nil {
		return nil
	}
	var out []Match
	for _, r := range e.rules {
		if _, ok := r.types[ev.Raw.EventType]; !ok {
			continue
		}
		if r.flags != 0 && ev.Raw.Flags&r.flags == 0 {
			continue
		}
		if r.once {
			if _, seen := e.once.LoadOrStore(r.name, struct{}{}); seen {
				continue
			}
		}
		out = append(out, Match{RuleName: r.name, Severity: r.severity, Event: ev})
	}
	return out
}

// EmitLogs writes rule matches to stderr/journald.
func EmitLogs(matches []Match) {
	for _, m := range matches {
		ev := m.Event
		log.Printf("RULE [%s] %s pid=%d comm=%s binary=%s path=%s dest=%s:%d mitre=%v",
			m.Severity, m.RuleName, ev.Raw.PID, ev.Raw.CommString(), ev.Binary, ev.Raw.OpenPath(),
			ev.Raw.FormatDestIP(), ev.Raw.DestPort, ev.MitreTags)
	}
}

func parseEventType(s string) (uint8, bool) {
	switch s {
	case "exec":
		return ringbuf.EventExec, true
	case "connect":
		return ringbuf.EventConnect, true
	case "ptrace":
		return ringbuf.EventPtrace, true
	case "openat", "open":
		return ringbuf.EventOpenat, true
	case "setuid":
		return ringbuf.EventSetuid, true
	case "setgid":
		return ringbuf.EventSetgid, true
	case "capset":
		return ringbuf.EventCapset, true
	case "bind":
		return ringbuf.EventBind, true
	case "dns":
		return ringbuf.EventDNS, true
	case "fork":
		return ringbuf.EventFork, true
	case "exit":
		return ringbuf.EventExit, true
	case "write":
		return ringbuf.EventWrite, true
	case "oom":
		return ringbuf.EventOOMKill, true
	default:
		return 0, false
	}
}

func parseFlag(s string) uint8 {
	switch s {
	case "sudo":
		return ringbuf.FlagSudo
	case "suspicious_port":
		return ringbuf.FlagSuspiciousPort
	case "sensitive_file":
		return ringbuf.FlagSensitiveFile
	case "tmp_file":
		return ringbuf.FlagTmpFile
	default:
		return 0
	}
}
