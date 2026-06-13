//go:build bpf_test

package bpf_test

import (
	"testing"

	"ebpf-agent/internal/ringbuf"
)

// BPF_PROG_RUN requires CAP_BPF and a loaded object; layout parity is tested in ringbuf/layout_test.go.
func TestBPFProgramHarness(t *testing.T) {
	if ringbuf.EventHeaderSize != 72 {
		t.Fatalf("expected 72-byte BPF header, got %d", ringbuf.EventHeaderSize)
	}
}
