package socket

import (
	"bytes"
	"net"
	"testing"

	"paqet/internal/conf"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// buildSyntheticFrame produces an Ethernet+IP+TCP+payload byte stream the
// same way send_handle would emit one. Used to feed both the gopacket
// reference parser and our hand-rolled parser to verify they extract the
// same (srcIP, srcPort, payload) tuple.
//
// We deliberately use the production hand-rolled emitter to build the
// frame — alpha.23's TestSerializeEquivalence already proves that's byte-
// identical to gopacket's output, so the input to this test is the same
// bytes both parsers will see in production.
func buildSyntheticFrame(t testing.TB, h *SendHandle, payload []byte, pf packetFields) []byte {
	scratch := make([]byte, maxPacketSize(len(payload)))
	n := h.serializePacketTo(scratch, payload, pf)
	out := make([]byte, n)
	copy(out, scratch[:n])
	return out
}

// gopacketParse extracts (srcIP, srcPort, payload) using the same
// gopacket calls the OLD recv_handle.Read used. Reference for equivalence.
func gopacketParse(data []byte) (net.IP, uint16, []byte, bool) {
	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

	netLayer := p.NetworkLayer()
	if netLayer == nil {
		return nil, 0, nil, false
	}
	var srcIP net.IP
	switch netLayer.LayerType() {
	case layers.LayerTypeIPv4:
		srcIP = netLayer.(*layers.IPv4).SrcIP
	case layers.LayerTypeIPv6:
		srcIP = netLayer.(*layers.IPv6).SrcIP
	default:
		return nil, 0, nil, false
	}

	trLayer := p.TransportLayer()
	if trLayer == nil {
		return nil, 0, nil, false
	}
	tcp, ok := trLayer.(*layers.TCP)
	if !ok {
		return nil, 0, nil, false
	}

	appLayer := p.ApplicationLayer()
	var payload []byte
	if appLayer != nil {
		payload = appLayer.Payload()
	}
	return srcIP, uint16(tcp.SrcPort), payload, true
}

func TestParseInboundEquivalence(t *testing.T) {
	h := mkTestHandle()

	flagCases := []conf.TCPF{
		{PSH: true, ACK: true},
		{SYN: true},
		{SYN: true, ACK: true},
		{FIN: true, ACK: true},
		{RST: true},
		{ACK: true},
	}
	dstIPs := []net.IP{
		net.IPv4(192, 168, 1, 100),
		net.IPv4(8, 8, 8, 8),
		net.ParseIP("2001:db8::42"),
	}
	payloadLens := []int{0, 1, 23, 1400, 9000}

	for _, flags := range flagCases {
		for _, dstIP := range dstIPs {
			for _, pl := range payloadLens {
				payload := make([]byte, pl)
				for i := range payload {
					payload[i] = byte((pl*7 + i*13) & 0xFF)
				}
				pf := packetFields{
					dstIP:   dstIP,
					dstPort: 12345,
					flags:   flags,
					seq:     0xCAFEBABE,
					ack:     0x12345678,
					tsVal:   0xAABBCCDD,
				}
				if !flags.SYN {
					pf.tsEcr = 0xDEADBEEF
				}

				frame := buildSyntheticFrame(t, h, payload, pf)

				wantIP, wantPort, wantPayload, wantOK := gopacketParse(frame)
				gotIP, gotPort, gotPayload, gotOK := parseInbound(frame)

				if wantOK != gotOK {
					t.Fatalf("ok mismatch: gopacket=%v handrolled=%v (flags=%+v dstIP=%v plen=%d)", wantOK, gotOK, flags, dstIP, pl)
				}
				if !wantOK {
					continue
				}

				// IP equality: the production wire is what the SENDER chose
				// as dstIP (in our packetFields), so that's the SOURCE the
				// receiver sees. Both parsers should extract the same
				// bytes, comparing as net.IP (handles 4-vs-16 byte forms).
				if !equalIP(wantIP, gotIP) {
					t.Fatalf("srcIP mismatch: got %v want %v (flags=%+v dstIP=%v plen=%d)", gotIP, wantIP, flags, dstIP, pl)
				}
				if wantPort != gotPort {
					t.Fatalf("srcPort mismatch: got %d want %d", gotPort, wantPort)
				}
				if !bytes.Equal(wantPayload, gotPayload) {
					t.Fatalf("payload mismatch: lengths got=%d want=%d", len(gotPayload), len(wantPayload))
				}
			}
		}
	}
}

func equalIP(a, b net.IP) bool {
	// net.IP allows 4-byte and 16-byte forms for IPv4; .Equal handles both.
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return a.Equal(b)
}

// Edge case: runt frame (too short for any IP header) must be rejected
// without panic.
func TestParseInboundRuntFrames(t *testing.T) {
	cases := [][]byte{
		nil,
		make([]byte, 1),
		make([]byte, 14),  // ethernet header only
		make([]byte, 33),  // eth + partial IPv4
		make([]byte, 14 + ipv4HdrSize + 10), // eth + ipv4 + half TCP
	}
	for i, c := range cases {
		_, _, _, ok := parseInbound(c)
		if ok {
			t.Fatalf("case %d (%d bytes) wrongly accepted", i, len(c))
		}
	}
}

// Edge case: IP declares larger total length than the actual buffer.
func TestParseInboundDeclaredOverrun(t *testing.T) {
	h := mkTestHandle()
	pf := packetFields{
		dstIP: net.IPv4(192, 168, 1, 100), dstPort: 1, flags: conf.TCPF{ACK: true},
		seq: 1, ack: 1, tsVal: 1, tsEcr: 1,
	}
	frame := buildSyntheticFrame(t, h, make([]byte, 100), pf)
	// Corrupt the IPv4 TotalLength field to claim more bytes than we have.
	frame[ethHdrSize+2] = 0xFF
	frame[ethHdrSize+3] = 0xFF
	if _, _, _, ok := parseInbound(frame); ok {
		t.Fatal("declared overrun was wrongly accepted")
	}
}

// Edge case: IP protocol is not TCP — should be rejected.
func TestParseInboundNonTCP(t *testing.T) {
	h := mkTestHandle()
	pf := packetFields{
		dstIP: net.IPv4(192, 168, 1, 100), dstPort: 1, flags: conf.TCPF{ACK: true},
		seq: 1, ack: 1, tsVal: 1, tsEcr: 1,
	}
	frame := buildSyntheticFrame(t, h, make([]byte, 64), pf)
	frame[ethHdrSize+9] = 17 // UDP
	if _, _, _, ok := parseInbound(frame); ok {
		t.Fatal("non-TCP protocol was wrongly accepted")
	}
}

func BenchmarkParseInbound_Gopacket_1400(b *testing.B) {
	h := mkTestHandle()
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	pf := packetFields{
		dstIP: net.IPv4(192, 168, 1, 100), dstPort: 443,
		flags: conf.TCPF{PSH: true, ACK: true},
		seq:   1, ack: 1, tsVal: 1, tsEcr: 1,
	}
	frame := buildSyntheticFrame(b, h, payload, pf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = gopacketParse(frame)
	}
}

func BenchmarkParseInbound_Handrolled_1400(b *testing.B) {
	h := mkTestHandle()
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	pf := packetFields{
		dstIP: net.IPv4(192, 168, 1, 100), dstPort: 443,
		flags: conf.TCPF{PSH: true, ACK: true},
		seq:   1, ack: 1, tsVal: 1, tsEcr: 1,
	}
	frame := buildSyntheticFrame(b, h, payload, pf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = parseInbound(frame)
	}
}

func BenchmarkParseInbound_Gopacket_64(b *testing.B) {
	h := mkTestHandle()
	payload := make([]byte, 64)
	pf := packetFields{
		dstIP: net.IPv4(192, 168, 1, 100), dstPort: 443,
		flags: conf.TCPF{PSH: true, ACK: true},
		seq:   1, ack: 1, tsVal: 1, tsEcr: 1,
	}
	frame := buildSyntheticFrame(b, h, payload, pf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = gopacketParse(frame)
	}
}

func BenchmarkParseInbound_Handrolled_64(b *testing.B) {
	h := mkTestHandle()
	payload := make([]byte, 64)
	pf := packetFields{
		dstIP: net.IPv4(192, 168, 1, 100), dstPort: 443,
		flags: conf.TCPF{PSH: true, ACK: true},
		seq:   1, ack: 1, tsVal: 1, tsEcr: 1,
	}
	frame := buildSyntheticFrame(b, h, payload, pf)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _, _ = parseInbound(frame)
	}
}
