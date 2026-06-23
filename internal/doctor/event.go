package doctor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"time"
)

const TaskCommLen = 16

// Event mirrors struct drop_event in bpf/drop_doctor.bpf.c.
type Event struct {
	TsNs      uint64
	Location  uint64
	Reason    uint32
	Ifindex   uint32
	Len       uint32
	Mark      uint32
	PID       uint32
	Protocol  uint16
	L4Proto   uint8
	IPVersion uint8
	SAddrV4   uint32
	DAddrV4   uint32
	SPort     uint16
	DPort     uint16
	Comm      [TaskCommLen]byte
}

func DecodeEvent(raw []byte) (Event, error) {
	var e Event
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &e); err != nil {
		return e, fmt.Errorf("decode event: %w", err)
	}
	return e, nil
}

func (e Event) Time() time.Time {
	return time.Unix(0, int64(e.TsNs))
}

func (e Event) CommString() string {
	return strings.TrimRight(string(e.Comm[:]), "\x00")
}

func (e Event) L4ProtoName() string {
	switch e.L4Proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 0:
		return "-"
	default:
		return fmt.Sprintf("IPPROTO_%d", e.L4Proto)
	}
}

func IPv4FromU32(v uint32) net.IP {
	// iphdr stores addresses in network byte order. Preserve the on-wire byte
	// order instead of treating it as host-endian integer text.
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return net.IPv4(b[0], b[1], b[2], b[3])
}

func (e Event) Flow() string {
	if e.IPVersion != 4 {
		return fmt.Sprintf("IPv%d", e.IPVersion)
	}

	src := IPv4FromU32(e.SAddrV4).String()
	dst := IPv4FromU32(e.DAddrV4).String()

	if e.SPort != 0 || e.DPort != 0 {
		return fmt.Sprintf("%s:%d -> %s:%d %s", src, e.SPort, dst, e.DPort, e.L4ProtoName())
	}
	return fmt.Sprintf("%s -> %s %s", src, dst, e.L4ProtoName())
}

func (e Event) ProtocolName() string {
	switch e.Protocol {
	case 0x0800:
		return "IPv4"
	case 0x86DD:
		return "IPv6"
	case 0:
		return "-"
	default:
		return fmt.Sprintf("0x%04x", e.Protocol)
	}
}
