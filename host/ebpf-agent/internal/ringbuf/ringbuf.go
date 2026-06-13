package ringbuf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	cringbuf "github.com/cilium/ebpf/ringbuf"
)

// EventHeaderSize is the fixed BPF/userspace event header (72 bytes).
const EventHeaderSize = 72

const (
	EventExec    uint8 = 1
	EventConnect uint8 = 2
	EventPtrace  uint8 = 3
	EventOpenat  uint8 = 4
	EventSetuid  uint8 = 5
	EventSetgid  uint8 = 6
	EventFork    uint8 = 7
	EventExit    uint8 = 8
	EventBind    uint8 = 9
	EventDNS     uint8 = 10
	EventCapset  uint8 = 11
	EventWrite   uint8 = 12
	EventOOMKill uint8 = 13
)

const (
	IPVersionNone uint8 = 0
	IPVersion4    uint8 = 4
	IPVersion6    uint8 = 6
)

const (
	FlagSudo           uint8 = 1 << 0
	FlagSuspiciousPort uint8 = 1 << 1
	FlagSensitiveFile  uint8 = 1 << 2
	FlagPasswdRead     uint8 = 1 << 3
	FlagTmpFile        uint8 = 1 << 4
)

type Event struct {
	TimestampNs uint64
	PID         uint32
	PPID        uint32
	UID         uint32
	EventType   uint8
	Flags       uint8
	DestPort    uint16
	IPVersion   uint8
	PathLen     uint8
	_           uint16
	CgroupID    uint64
	DestIP      [16]byte
	Comm        [16]byte
	Filename    string // exec events: variable-length tail after header
}

// DestIPv4U32 returns the first four bytes of DestIP as a uint32 (matches prior BPF sin_addr layout).
func (e *Event) DestIPv4U32() uint32 {
	return binary.LittleEndian.Uint32(e.DestIP[:4])
}

func (e *Event) CommString() string {
	for i, b := range e.Comm {
		if b == 0 {
			return string(e.Comm[:i])
		}
	}
	return string(e.Comm[:])
}

// FormatDestIP returns a display string for the destination address (IPv4 or IPv6).
func (e *Event) FormatDestIP() string {
	switch e.IPVersion {
	case IPVersion4:
		ip := e.DestIP[:4]
		return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
	case IPVersion6:
		return net.IP(e.DestIP[:]).String()
	default:
		return ""
	}
}

// ParseEvent decodes a ringbuf record (fixed header + optional filename tail).
func ParseEvent(data []byte) (*Event, error) {
	if len(data) < EventHeaderSize {
		return nil, errors.New("record too short")
	}
	e := &Event{
		TimestampNs: binary.LittleEndian.Uint64(data[0:8]),
		PID:         binary.LittleEndian.Uint32(data[8:12]),
		PPID:        binary.LittleEndian.Uint32(data[12:16]),
		UID:         binary.LittleEndian.Uint32(data[16:20]),
		EventType:   data[20],
		Flags:       data[21],
		DestPort:    binary.LittleEndian.Uint16(data[22:24]),
		IPVersion:   data[24],
		PathLen:     data[25],
		CgroupID:    binary.LittleEndian.Uint64(data[28:36]),
	}
	copy(e.DestIP[:], data[36:52])
	copy(e.Comm[:], data[52:68])

	if e.PathLen > 0 {
		end := EventHeaderSize + int(e.PathLen)
		if len(data) < end {
			return nil, fmt.Errorf("record tail too short: need %d bytes, got %d", end, len(data))
		}
		e.Filename = string(data[EventHeaderSize:end])
	}
	return e, nil
}

func parseEvent(data []byte) (*Event, error) {
	return ParseEvent(data)
}

type Consumer struct {
	reader *cringbuf.Reader
	out    chan *Event
	done   chan struct{}
	onDrop func()
}

func NewConsumer(eventsMap *ebpf.Map, bufSize int) (*Consumer, error) {
	rd, err := cringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, err
	}

	c := &Consumer{
		reader: rd,
		out:    make(chan *Event, bufSize),
		done:   make(chan struct{}),
	}
	return c, nil
}

func (c *Consumer) SetDropCallback(fn func()) {
	c.onDrop = fn
}

func (c *Consumer) Events() <-chan *Event {
	return c.out
}

// Run blocks, reading from the ringbuf and pushing to the channel.
// Call Close() to stop.
func (c *Consumer) Run() {
	defer close(c.out)
	for {
		record, err := c.reader.Read()
		if err != nil {
			if errors.Is(err, cringbuf.ErrClosed) {
				return
			}
			log.Printf("ringbuf read error: %v", err)
			continue
		}

		ev, err := parseEvent(record.RawSample)
		if err != nil {
			log.Printf("ringbuf parse error: %v", err)
			continue
		}

		select {
		case c.out <- ev:
		default:
			if c.onDrop != nil {
				c.onDrop()
			}
		}
	}
}

func (c *Consumer) Close() error {
	return c.reader.Close()
}
