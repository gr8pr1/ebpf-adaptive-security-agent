package aggregator

import (
	"path/filepath"
	"sync"
	"time"

	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/ringbuf"
)

// DimensionKey uniquely identifies a metric dimension for baselining.
type DimensionKey struct {
	MetricName string
	User       string
	Process    string
	Container  string
}

// Window holds aggregated counts for a single time window.
type Window struct {
	Start    time.Time
	End      time.Time
	Counts   map[DimensionKey]float64
}

// Aggregator collects enriched events into time-bucketed windows.
type Aggregator struct {
	windowSize   time.Duration
	perUser      bool
	perProcess   bool
	perCont      bool
	network      bool
	filesystem   bool
	scheduling   bool
	uniqueDestIP map[DimensionKey]map[string]struct{} // connect events only: dedupe dest IPs per dimension key

	mu      sync.Mutex
	current *Window
}

func New(windowSize time.Duration, perUser, perProcess, perContainer, network, filesystem, scheduling bool) *Aggregator {
	now := time.Now()
	return &Aggregator{
		windowSize:   windowSize,
		perUser:      perUser,
		perProcess:   perProcess,
		perCont:      perContainer,
		network:      network,
		filesystem:   filesystem,
		scheduling:   scheduling,
		uniqueDestIP: make(map[DimensionKey]map[string]struct{}),
		current: &Window{
			Start:  now,
			End:    now.Add(windowSize),
			Counts: make(map[DimensionKey]float64),
		},
	}
}

func (a *Aggregator) shouldInclude(ev *enricher.EnrichedEvent) bool {
	if !a.network {
		switch ev.Raw.EventType {
		case ringbuf.EventConnect, ringbuf.EventBind, ringbuf.EventDNS:
			return false
		}
	}
	if !a.filesystem && ev.Raw.EventType == ringbuf.EventOpenat {
		return false
	}
	if !a.scheduling {
		switch ev.Raw.EventType {
		case ringbuf.EventFork, ringbuf.EventExit:
			return false
		}
	}
	return true
}

func (a *Aggregator) Add(ev *enricher.EnrichedEvent) {
	if !a.shouldInclude(ev) {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	metricName := eventTypeToMetric(ev.Raw.EventType, ev.Raw.Flags)

	key := DimensionKey{MetricName: metricName}
	if a.perUser {
		key.User = ev.Username
	}
	if a.perProcess {
		if ev.Resolved && ev.Binary != "" {
			key.Process = "bin:" + filepath.Base(ev.Binary)
		} else {
			key.Process = "comm:" + ev.Raw.CommString()
		}
	}
	if a.perCont && ev.Container != "" {
		key.Container = ev.Container
	}

	a.current.Counts[key]++

	hostKey := DimensionKey{MetricName: metricName}
	if key != hostKey {
		a.current.Counts[hostKey]++
	}

	// unique_dest_ips: distinct destination IPs per dimension (connect only, not suspicious_connect)
	if metricName == "connect" && ev.Raw.IPVersion != ringbuf.IPVersionNone {
		ipStr := ev.Raw.FormatDestIP()
		if ipStr != "" {
			a.recordUniqueIPForConnect(key, ipStr)
			if hostKey != key {
				a.recordUniqueIPForConnect(hostKey, ipStr)
			}
		}
	}
}

func (a *Aggregator) recordUniqueIPForConnect(connectDim DimensionKey, ip string) {
	set, ok := a.uniqueDestIP[connectDim]
	if !ok {
		set = make(map[string]struct{})
		a.uniqueDestIP[connectDim] = set
	}
	if _, exists := set[ip]; exists {
		return
	}
	set[ip] = struct{}{}
	ud := connectDim
	ud.MetricName = "unique_dest_ips"
	a.current.Counts[ud]++
}

// Rotate closes the current window and returns it, starting a new one.
func (a *Aggregator) Rotate() *Window {
	a.mu.Lock()
	defer a.mu.Unlock()

	finished := a.current
	now := time.Now()
	a.uniqueDestIP = make(map[DimensionKey]map[string]struct{})
	a.current = &Window{
		Start:  now,
		End:    now.Add(a.windowSize),
		Counts: make(map[DimensionKey]float64),
	}
	return finished
}

func eventTypeToMetric(evType uint8, flags uint8) string {
	switch evType {
	case ringbuf.EventExec:
		if flags&ringbuf.FlagSudo != 0 {
			return "sudo"
		}
		if flags&ringbuf.FlagPasswdRead != 0 {
			return "passwd_read_exec"
		}
		return "exec"
	case ringbuf.EventConnect:
		if flags&ringbuf.FlagSuspiciousPort != 0 {
			return "suspicious_connect"
		}
		return "connect"
	case ringbuf.EventPtrace:
		return "ptrace"
	case ringbuf.EventOpenat:
		if flags&ringbuf.FlagPasswdRead != 0 {
			return "passwd_read_open"
		}
		if flags&ringbuf.FlagSensitiveFile != 0 {
			return "sensitive_file"
		}
		return "file_open"
	case ringbuf.EventSetuid:
		return "setuid"
	case ringbuf.EventSetgid:
		return "setgid"
	case ringbuf.EventFork:
		return "fork"
	case ringbuf.EventExit:
		return "exit"
	case ringbuf.EventBind:
		return "bind"
	case ringbuf.EventDNS:
		return "dns"
	case ringbuf.EventCapset:
		return "capset"
	default:
		return "unknown"
	}
}
