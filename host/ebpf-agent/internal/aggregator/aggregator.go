package aggregator

import (
	"fmt"
	"sync"
	"time"

	"ebpf-agent/internal/dimkey"
	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/ringbuf"
)

const shortLivedThresholdNs = 5 * uint64(time.Second)

// DimensionKey uniquely identifies a metric dimension for baselining.
type DimensionKey struct {
	MetricName string
	User       string
	Process    string
	Container  string
}

// Window holds aggregated counts for a single time window.
type Window struct {
	Start  time.Time
	End    time.Time
	Counts map[DimensionKey]float64
}

// Aggregator collects enriched events into time-bucketed windows.
type Aggregator struct {
	windowSize           time.Duration
	perUser              bool
	perProcess           bool
	perCont              bool
	network              bool
	filesystem           bool
	scheduling           bool
	normalizeBinary      bool
	preferImageName      bool
	uniqueDestIP         map[DimensionKey]map[string]struct{}

	pidExecNs map[uint32]uint64
	ppidForks map[uint32]float64

	mu      sync.Mutex
	current *Window
}

func New(windowSize time.Duration, perUser, perProcess, perContainer, network, filesystem, scheduling bool,
	normalizeBinary, preferImage bool,
) *Aggregator {
	now := time.Now()
	return &Aggregator{
		windowSize:   windowSize,
		perUser:      perUser,
		perProcess:   perProcess,
		perCont:      perContainer,
		network:      network,
		filesystem:   filesystem,
		scheduling:      scheduling,
		normalizeBinary: normalizeBinary,
		preferImageName: preferImage,
		uniqueDestIP:    make(map[DimensionKey]map[string]struct{}),
		pidExecNs:    make(map[uint32]uint64),
		ppidForks:    make(map[uint32]float64),
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
	if !a.filesystem {
		switch ev.Raw.EventType {
		case ringbuf.EventOpenat, ringbuf.EventWrite:
			return false
		}
	}
	if !a.scheduling {
		switch ev.Raw.EventType {
		case ringbuf.EventFork, ringbuf.EventExit, ringbuf.EventOOMKill:
			return false
		}
	}
	return true
}

func (a *Aggregator) dimensionKey(metricName string, ev *enricher.EnrichedEvent) DimensionKey {
	key := DimensionKey{MetricName: metricName}
	if a.perUser {
		key.User = ev.Username
	}
	if a.perProcess {
		label := dimkey.ProcessLabel(ev.Binary, ev.Raw.CommString(), a.normalizeBinary)
		if label != "" {
			key.Process = label
		}
	}
	if a.perCont && ev.Container != "" {
		key.Container = dimkey.NormalizeContainer(ev.Container, a.preferImageName)
	}
	return key
}

func (a *Aggregator) increment(metricName string, ev *enricher.EnrichedEvent) {
	key := a.dimensionKey(metricName, ev)
	a.current.Counts[key]++

	hostKey := DimensionKey{MetricName: metricName}
	if key != hostKey {
		a.current.Counts[hostKey]++
	}
}

func (a *Aggregator) Add(ev *enricher.EnrichedEvent) {
	if !a.shouldInclude(ev) {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	metricName := eventTypeToMetric(ev.Raw.EventType, ev.Raw.Flags)
	a.increment(metricName, ev)

	switch ev.Raw.EventType {
	case ringbuf.EventExec:
		a.pidExecNs[ev.Raw.PID] = ev.Raw.TimestampNs
	case ringbuf.EventFork:
		if ev.Raw.PPID > 0 {
			a.ppidForks[ev.Raw.PPID]++
			if a.ppidForks[ev.Raw.PPID] >= 50 {
				dk := DimensionKey{MetricName: "fork_bomb_score"}
				if a.perProcess {
					dk.Process = fmt.Sprintf("ppid:%d", ev.Raw.PPID)
				}
				a.current.Counts[dk] = a.ppidForks[ev.Raw.PPID]
			}
		}
	case ringbuf.EventExit:
		if start, ok := a.pidExecNs[ev.Raw.PID]; ok {
			if ev.Raw.TimestampNs > start && ev.Raw.TimestampNs-start < shortLivedThresholdNs {
				a.increment("short_lived_process", ev)
			}
			delete(a.pidExecNs, ev.Raw.PID)
		}
	}

	if metricName == "connect" && ev.Raw.IPVersion != ringbuf.IPVersionNone {
		ipStr := ev.Raw.FormatDestIP()
		if ipStr != "" {
			key := a.dimensionKey("connect", ev)
			a.recordUniqueIPForConnect(key, ipStr)
			hostKey := DimensionKey{MetricName: "connect"}
			if key != hostKey {
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
	a.ppidForks = make(map[uint32]float64)
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
		return "exec"
	case ringbuf.EventConnect:
		if flags&ringbuf.FlagSuspiciousPort != 0 {
			return "suspicious_connect"
		}
		return "connect"
	case ringbuf.EventPtrace:
		return "ptrace"
	case ringbuf.EventOpenat:
		if flags&ringbuf.FlagSensitiveFile != 0 {
			return "sensitive_file"
		}
		if flags&ringbuf.FlagTmpFile != 0 {
			return "tmp_file_creation_rate"
		}
		return "file_open"
	case ringbuf.EventWrite:
		return "file_write_rate"
	case ringbuf.EventOOMKill:
		return "oom_kill"
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
