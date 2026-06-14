package socket

import (
	"bytes"
	"net"
	"testing"

	"paqet/internal/conf"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// gopacketEmit produces the same bytes the production Write() function
// emits today, parameterized so tests can fix the volatile fields. Used
// only as the gold-standard reference in TestSerializeEquivalence.
func gopacketEmit(h *SendHandle, payload []byte, pf packetFields) []byte {
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(h.srcPort),
		DstPort: layers.TCPPort(pf.dstPort),
		FIN:     pf.flags.FIN, SYN: pf.flags.SYN, RST: pf.flags.RST, PSH: pf.flags.PSH,
		ACK: pf.flags.ACK, URG: pf.flags.URG, ECE: pf.flags.ECE, CWR: pf.flags.CWR, NS: pf.flags.NS,
		Window: 65535,
		Seq:    pf.seq,
		Ack:    pf.ack,
	}
	if pf.flags.SYN {
		ts := make([]byte, 8)
		bigEndianPutUint32(ts[0:4], pf.tsVal)
		bigEndianPutUint32(ts[4:8], 0)
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
			{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: ts},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
		}
	} else {
		ts := make([]byte, 8)
		bigEndianPutUint32(ts[0:4], pf.tsVal)
		bigEndianPutUint32(ts[4:8], pf.tsEcr)
		tcp.Options = []layers.TCPOption{
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindNop},
			{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: ts},
		}
	}

	eth := &layers.Ethernet{SrcMAC: h.cfgInterfaceMAC}
	var ipLayer gopacket.SerializableLayer
	if pf.dstIP.To4() != nil {
		ip := &layers.IPv4{
			Version: 4, IHL: 5, TOS: 184, TTL: 64,
			Flags:    layers.IPv4DontFragment,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    h.srcIPv4,
			DstIP:    pf.dstIP,
		}
		ipLayer = ip
		tcp.SetNetworkLayerForChecksum(ip)
		eth.DstMAC = h.srcIPv4RHWA
		eth.EthernetType = layers.EthernetTypeIPv4
	} else {
		ip := &layers.IPv6{
			Version: 6, TrafficClass: 184, HopLimit: 64,
			NextHeader: layers.IPProtocolTCP,
			SrcIP:      h.srcIPv6,
			DstIP:      pf.dstIP,
		}
		ipLayer = ip
		tcp.SetNetworkLayerForChecksum(ip)
		eth.DstMAC = h.srcIPv6RHWA
		eth.EthernetType = layers.EthernetTypeIPv6
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ipLayer, tcp, gopacket.Payload(payload)); err != nil {
		panic(err)
	}
	out := make([]byte, len(buf.Bytes()))
	copy(out, buf.Bytes())
	return out
}

// bigEndianPutUint32 is a tiny local helper so the test file doesn't have
// to import encoding/binary itself.
func bigEndianPutUint32(b []byte, v uint32) {
	b[0] = byte(v >> 24)
	b[1] = byte(v >> 16)
	b[2] = byte(v >> 8)
	b[3] = byte(v)
}

func mkTestHandle() *SendHandle {
	return &SendHandle{
		srcIPv4:         net.IPv4(10, 0, 0, 1),
		srcIPv6:         net.ParseIP("2001:db8::1"),
		srcIPv4RHWA:     net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x01},
		srcIPv6RHWA:     net.HardwareAddr{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x02},
		cfgInterfaceMAC: net.HardwareAddr{0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0x01},
		srcPort:         55555,
	}
}

func TestSerializeEquivalence(t *testing.T) {
	h := mkTestHandle()

	flagCases := []conf.TCPF{
		{PSH: true, ACK: true},
		{SYN: true},
		{SYN: true, ACK: true},
		{FIN: true, ACK: true},
		{RST: true},
		{ACK: true},
		{}, // bare segment
	}
	addrCases := []net.IP{
		net.IPv4(192, 168, 1, 100),
		net.IPv4(8, 8, 8, 8),
		net.ParseIP("2001:db8::42"),
	}
	payloadCases := [][]byte{
		nil,
		make([]byte, 1),
		make([]byte, 23),
		make([]byte, 1400),
		make([]byte, 65000),
	}
	for i, p := range payloadCases {
		for j := range p {
			p[j] = byte(i*131 + j*7)
		}
	}

	scratch := make([]byte, maxPacketSize(65000))
	for _, flags := range flagCases {
		for _, dstIP := range addrCases {
			for _, payload := range payloadCases {
				pf := packetFields{
					dstIP:   dstIP,
					dstPort: 12345,
					flags:   flags,
					seq:     0x11223344,
					ack:     0x55667788,
					tsVal:   0x99AABBCC,
				}
				if !flags.SYN {
					pf.tsEcr = 0xDEADBEEF
				}
				want := gopacketEmit(h, payload, pf)
				n := h.serializePacketTo(scratch, payload, pf)
				got := scratch[:n]
				if !bytes.Equal(got, want) {
					t.Logf("flags=%+v dstIP=%v payloadLen=%d", flags, dstIP, len(payload))
					t.Logf("got  len=%d", len(got))
					t.Logf("want len=%d", len(want))
					mismatchDump(t, got, want)
					t.FailNow()
				}
			}
		}
	}
}

func mismatchDump(t *testing.T, got, want []byte) {
	t.Helper()
	n := len(got)
	if len(want) < n {
		n = len(want)
	}
	for i := 0; i < n; i++ {
		if got[i] != want[i] {
			start := i - 4
			if start < 0 {
				start = 0
			}
			end := i + 16
			if end > n {
				end = n
			}
			t.Logf("first diff at byte %d", i)
			t.Logf("got  [%d:%d] = % x", start, end, got[start:end])
			t.Logf("want [%d:%d] = % x", start, end, want[start:end])
			return
		}
	}
	if len(got) != len(want) {
		t.Logf("length mismatch: got=%d want=%d", len(got), len(want))
	}
}

func BenchmarkSerialize_Gopacket_1400(b *testing.B) {
	h := mkTestHandle()
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	pf := packetFields{
		dstIP:   net.IPv4(192, 168, 1, 100),
		dstPort: 443,
		flags:   conf.TCPF{PSH: true, ACK: true},
		seq:     0x11223344,
		ack:     0x55667788,
		tsVal:   0x99AABBCC,
		tsEcr:   0xDEADBEEF,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gopacketEmit(h, payload, pf)
	}
}

func BenchmarkSerialize_Handrolled_1400(b *testing.B) {
	h := mkTestHandle()
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i)
	}
	pf := packetFields{
		dstIP:   net.IPv4(192, 168, 1, 100),
		dstPort: 443,
		flags:   conf.TCPF{PSH: true, ACK: true},
		seq:     0x11223344,
		ack:     0x55667788,
		tsVal:   0x99AABBCC,
		tsEcr:   0xDEADBEEF,
	}
	scratch := make([]byte, maxPacketSize(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.serializePacketTo(scratch, payload, pf)
	}
}

func BenchmarkSerialize_Gopacket_64(b *testing.B) {
	h := mkTestHandle()
	payload := make([]byte, 64)
	pf := packetFields{
		dstIP: net.IPv4(192, 168, 1, 100), dstPort: 443,
		flags: conf.TCPF{PSH: true, ACK: true},
		seq:   1, ack: 1, tsVal: 1, tsEcr: 1,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = gopacketEmit(h, payload, pf)
	}
}

func BenchmarkSerialize_Handrolled_64(b *testing.B) {
	h := mkTestHandle()
	payload := make([]byte, 64)
	pf := packetFields{
		dstIP: net.IPv4(192, 168, 1, 100), dstPort: 443,
		flags: conf.TCPF{PSH: true, ACK: true},
		seq:   1, ack: 1, tsVal: 1, tsEcr: 1,
	}
	scratch := make([]byte, maxPacketSize(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = h.serializePacketTo(scratch, payload, pf)
	}
}
