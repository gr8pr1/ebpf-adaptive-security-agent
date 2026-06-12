package mitre

import (
	"net"
	"path/filepath"
	"strings"

	"ebpf-agent/internal/enricher"
	"ebpf-agent/internal/ringbuf"
)

type Technique struct {
	ID     string
	Name   string
	Tactic string
}

type Mapping struct {
	Techniques []Technique
}

var shellBinaries = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true,
	"fish": true, "csh": true, "tcsh": true, "ksh": true,
}

var scriptInterpreters = map[string]Technique{
	"python":  {ID: "T1059.006", Name: "Python", Tactic: "Execution"},
	"python2": {ID: "T1059.006", Name: "Python", Tactic: "Execution"},
	"python3": {ID: "T1059.006", Name: "Python", Tactic: "Execution"},
	"perl":    {ID: "T1059.006", Name: "Perl", Tactic: "Execution"},
	"ruby":    {ID: "T1059.006", Name: "Ruby", Tactic: "Execution"},
	"node":    {ID: "T1059.007", Name: "JavaScript", Tactic: "Execution"},
	"lua":     {ID: "T1059", Name: "Command and Scripting Interpreter", Tactic: "Execution"},
}

var cronParents = map[string]bool{
	"cron": true, "crond": true, "anacron": true, "atd": true,
}

func Map(ev *enricher.EnrichedEvent) Mapping {
	switch ev.Raw.EventType {
	case ringbuf.EventExec:
		return mapExec(ev)
	case ringbuf.EventConnect:
		return mapConnect(ev)
	case ringbuf.EventPtrace:
		return Mapping{Techniques: []Technique{
			{ID: "T1055", Name: "Process Injection", Tactic: "Defense Evasion"},
		}}
	case ringbuf.EventOpenat:
		return mapOpenat(ev)
	case ringbuf.EventSetuid:
		return mapPrivEsc(ev, "setuid")
	case ringbuf.EventSetgid:
		return mapPrivEsc(ev, "setgid")
	case ringbuf.EventCapset:
		return Mapping{Techniques: []Technique{
			{ID: "T1548.001", Name: "Setuid and Setgid", Tactic: "Privilege Escalation"},
		}}
	case ringbuf.EventBind:
		return mapBind(ev)
	case ringbuf.EventDNS:
		return Mapping{Techniques: []Technique{
			{ID: "T1071.004", Name: "DNS", Tactic: "Command and Control"},
		}}
	case ringbuf.EventFork, ringbuf.EventExit:
		return Mapping{}
	default:
		return Mapping{}
	}
}

func mapExec(ev *enricher.EnrichedEvent) Mapping {
	comm := ev.Raw.CommString()
	var base string
	if ev.Binary != "" {
		base = filepath.Base(ev.Binary)
	}
	var techniques []Technique

	if ev.Raw.Flags&ringbuf.FlagSudo != 0 {
		techniques = append(techniques, Technique{
			ID: "T1548.003", Name: "Sudo and Sudo Caching", Tactic: "Privilege Escalation",
		})
	}

	if shellBinaries[comm] || shellBinaries[base] {
		techniques = append(techniques, Technique{
			ID: "T1059.004", Name: "Unix Shell", Tactic: "Execution",
		})
	} else if t, ok := scriptInterpreters[comm]; ok {
		techniques = append(techniques, t)
	} else if t, ok := scriptInterpreters[base]; ok {
		techniques = append(techniques, t)
	}

	if cronParents[comm] {
		techniques = append(techniques, Technique{
			ID: "T1053.003", Name: "Cron", Tactic: "Persistence",
		})
	}

	if base != "" && comm != "" && base != comm {
		prefixOK := strings.HasPrefix(base, comm) &&
			(len(base) == len(comm) || base[len(comm)] == '.')
		if !prefixOK {
			techniques = append(techniques, Technique{
				ID: "T1036.003", Name: "Rename System Utilities", Tactic: "Defense Evasion",
			})
		}
	}

	if len(techniques) == 0 {
		techniques = append(techniques, Technique{
			ID: "T1106", Name: "Native API", Tactic: "Execution",
		})
	}

	return Mapping{Techniques: techniques}
}

func mapConnect(ev *enricher.EnrichedEvent) Mapping {
	var techniques []Technique

	if ev.Raw.Flags&ringbuf.FlagSuspiciousPort != 0 {
		techniques = append(techniques, Technique{
			ID: "T1571", Name: "Non-Standard Port", Tactic: "Command and Control",
		})
	}

	port := ev.Raw.DestPort
	switch {
	case port == 443 || port == 80:
		techniques = append(techniques, Technique{
			ID: "T1071.001", Name: "Web Protocols", Tactic: "Command and Control",
		})
	case port == 22:
		techniques = append(techniques, Technique{
			ID: "T1021.004", Name: "SSH", Tactic: "Lateral Movement",
		})
	}

	switch ev.Raw.IPVersion {
	case ringbuf.IPVersion4:
		if isRFC1918(ev.Raw.DestIPv4U32()) {
			techniques = append(techniques, Technique{
				ID: "T1021", Name: "Remote Services", Tactic: "Lateral Movement",
			})
		}
	case ringbuf.IPVersion6:
		if isIPv6PrivateOrULA(net.IP(ev.Raw.DestIP[:])) {
			techniques = append(techniques, Technique{
				ID: "T1021", Name: "Remote Services", Tactic: "Lateral Movement",
			})
		}
	}

	if len(techniques) == 0 {
		techniques = append(techniques, Technique{
			ID: "T1071", Name: "Application Layer Protocol", Tactic: "Command and Control",
		})
	}

	return Mapping{Techniques: techniques}
}

func mapOpenat(ev *enricher.EnrichedEvent) Mapping {
	if ev.Raw.Flags&ringbuf.FlagPasswdRead != 0 {
		return Mapping{Techniques: []Technique{
			{ID: "T1003.008", Name: "/etc/passwd and /etc/shadow", Tactic: "Credential Access"},
		}}
	}
	if ev.Raw.Flags&ringbuf.FlagSensitiveFile != 0 {
		return Mapping{Techniques: []Technique{
			{ID: "T1003.008", Name: "/etc/passwd and /etc/shadow", Tactic: "Credential Access"},
		}}
	}
	return Mapping{Techniques: []Technique{
		{ID: "T1005", Name: "Data from Local System", Tactic: "Collection"},
	}}
}

func mapPrivEsc(ev *enricher.EnrichedEvent, kind string) Mapping {
	return Mapping{Techniques: []Technique{
		{ID: "T1548.001", Name: "Setuid and Setgid", Tactic: "Privilege Escalation"},
	}}
}

func mapBind(ev *enricher.EnrichedEvent) Mapping {
	port := ev.Raw.DestPort
	if port > 0 && port < 1024 {
		return Mapping{Techniques: []Technique{
			{ID: "T1205", Name: "Traffic Signaling", Tactic: "Persistence"},
		}}
	}
	return Mapping{Techniques: []Technique{
		{ID: "T1046", Name: "Network Service Discovery", Tactic: "Discovery"},
	}}
}

func isRFC1918(ip uint32) bool {
	b0 := byte(ip & 0xFF)
	b1 := byte((ip >> 8) & 0xFF)
	if b0 == 10 {
		return true
	}
	if b0 == 172 && b1 >= 16 && b1 <= 31 {
		return true
	}
	if b0 == 192 && b1 == 168 {
		return true
	}
	return false
}

// isIPv6PrivateOrULA matches ULA (fc00::/7) and link-local (fe80::/10).
func isIPv6PrivateOrULA(ip net.IP) bool {
	if len(ip) != 16 {
		return false
	}
	if ip[0] == 0xfe && (ip[1]&0xc0) == 0x80 {
		return true
	}
	if (ip[0] & 0xfe) == 0xfc {
		return true
	}
	return false
}
