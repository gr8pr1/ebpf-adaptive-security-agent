package dimkey

import (
	"path/filepath"
	"regexp"
	"strings"
)

var versionSuffix = regexp.MustCompile(`^(.+?)(?:\.[0-9]+)+$`)

// NormalizeBinary strips version-like suffixes from a binary basename (python3.11 -> python3).
func NormalizeBinary(base string, enabled bool) string {
	if !enabled || base == "" {
		return base
	}
	if m := versionSuffix.FindStringSubmatch(base); len(m) == 2 {
		return m[1]
	}
	return base
}

// NormalizeContainer prefers a stable image/service name over ephemeral instance IDs.
func NormalizeContainer(name string, preferImage bool) string {
	if !preferImage || name == "" {
		return name
	}
	if strings.HasPrefix(name, "cgroup:") {
		return name
	}
	// docker-abc123.scope -> docker (image family hint)
	if strings.HasPrefix(name, "docker-") && strings.HasSuffix(name, ".scope") {
		return "docker"
	}
	// k8s pod uid fragments: keep first segment if slash-separated
	if idx := strings.Index(name, "/"); idx > 0 {
		return name[:idx]
	}
	return name
}

// ProcessLabel builds the per-process dimension label.
func ProcessLabel(binary, comm string, normalizeBinary bool) string {
	if binary != "" {
		return "bin:" + NormalizeBinary(filepath.Base(binary), normalizeBinary)
	}
	if comm != "" {
		return "comm:" + comm
	}
	return ""
}
