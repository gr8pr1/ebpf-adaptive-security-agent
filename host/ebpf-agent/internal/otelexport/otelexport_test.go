package otelexport

import (
	"testing"

	"ebpf-agent/internal/ringbuf"
)

func TestSampleRateFlagAwareness(t *testing.T) {
	m := map[string]float64{
		"connect":            0.01,
		"suspicious_connect": 1.0,
		"exec":               0.01,
		"sudo":               1.0,
		"passwd_read":        1.0,
		"sensitive_file":     1.0,
	}

	if got := SampleRate(m, ringbuf.EventConnect, ringbuf.FlagSuspiciousPort); got != 1.0 {
		t.Fatalf("suspicious connect: got %f want 1.0", got)
	}
	if got := SampleRate(m, ringbuf.EventConnect, 0); got != 0.01 {
		t.Fatalf("routine connect: got %f want 0.01", got)
	}
	if got := SampleRate(m, ringbuf.EventExec, ringbuf.FlagSudo); got != 1.0 {
		t.Fatalf("sudo exec: got %f want 1.0", got)
	}
	if got := SampleRate(m, ringbuf.EventExec, ringbuf.FlagPasswdRead); got != 1.0 {
		t.Fatalf("passwd exec: got %f want 1.0", got)
	}
	if got := SampleRate(m, ringbuf.EventOpenat, ringbuf.FlagSensitiveFile); got != 1.0 {
		t.Fatalf("sensitive openat: got %f want 1.0", got)
	}
}

func TestShouldSampleNoOverflow(t *testing.T) {
	// Large timestamp should not produce negative modulo behavior.
	ts := uint64(18446744073709551615)
	if !shouldSample(ts, 1.0) {
		t.Fatal("rate 1.0 should always sample")
	}
	if shouldSample(ts, 0.0) {
		t.Fatal("rate 0.0 should never sample")
	}
}
