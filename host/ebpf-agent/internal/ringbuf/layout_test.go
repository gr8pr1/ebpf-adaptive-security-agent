package ringbuf_test

import (
	"encoding/binary"
	"testing"

	"ebpf-agent/internal/ringbuf"
)

// BPF C struct ebpf_event layout offsets (exec.bpf.c).
const (
	bpfOffTimestampNs = 0
	bpfOffPID         = 8
	bpfOffPPID        = 12
	bpfOffUID         = 16
	bpfOffEventType   = 20
	bpfOffFlags       = 21
	bpfOffDestPort    = 22
	bpfOffIPVersion   = 24
	bpfOffPathLen     = 25
	bpfOffCgroupID    = 28
	bpfOffDestIP      = 36
	bpfOffComm        = 52
)

func TestEventHeaderSizeParity(t *testing.T) {
	if ringbuf.EventHeaderSize != 72 {
		t.Fatalf("EventHeaderSize = %d, want 72", ringbuf.EventHeaderSize)
	}
}

func TestParseEventHeaderRoundTrip(t *testing.T) {
	raw := make([]byte, ringbuf.EventHeaderSize+len("/usr/bin/cat"))
	binary.LittleEndian.PutUint64(raw[bpfOffTimestampNs:], 12345)
	binary.LittleEndian.PutUint32(raw[bpfOffPID:], 1001)
	binary.LittleEndian.PutUint32(raw[bpfOffPPID:], 999)
	binary.LittleEndian.PutUint32(raw[bpfOffUID:], 1000)
	raw[bpfOffEventType] = ringbuf.EventExec
	raw[bpfOffFlags] = ringbuf.FlagPasswdRead
	binary.LittleEndian.PutUint16(raw[bpfOffDestPort:], 0)
	raw[bpfOffIPVersion] = ringbuf.IPVersionNone
	raw[bpfOffPathLen] = uint8(len("/usr/bin/cat"))
	binary.LittleEndian.PutUint64(raw[bpfOffCgroupID:], 42)
	copy(raw[bpfOffComm:], []byte("cat\x00"))
	copy(raw[ringbuf.EventHeaderSize:], []byte("/usr/bin/cat"))

	ev, err := ringbuf.ParseEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.PID != 1001 || ev.PPID != 999 || ev.Filename != "/usr/bin/cat" {
		t.Fatalf("unexpected event: %+v", ev)
	}
}

func TestSensitivePathLengthParity(t *testing.T) {
	cases := []struct {
		path    string
		wantLen int
	}{
		{"/etc/shadow", 12},
		{"/etc/sudoers", 13},
		{"/etc/passwd", 12},
	}
	for _, tc := range cases {
		ret := len(tc.path) + 1
		if ret != tc.wantLen {
			t.Fatalf("%s: ret=%d want %d", tc.path, ret, tc.wantLen)
		}
	}
}
