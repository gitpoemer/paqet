package socket

import (
	"encoding/binary"
	"net"
	"testing"
)

// rawFrame is a low-level test helper that builds an arbitrary Ethernet+
// IP+TCP+payload frame WITHOUT going through the production hand-rolled
// emitter — so tests can construct malformed or edge-case packets
// (fragments, IP options, VLAN tags, jumbo frames, etc.) that the
// production emitter never produces.
type rawFrame struct {
	ethType uint16

	// IPv4 fields
	v4IHL      int    // header words; 5 = 20 bytes, 15 = 60 bytes
	v4TotalLen int    // 0 = auto-fill
	v4FlagsFrag uint16 // raw 16-bit value (DF=0x4000, MF=0x2000, offset bits=0x1FFF)
	v4Protocol byte
	v4SrcIP    [4]byte
	v4DstIP    [4]byte
	v4OptsPad  []byte // raw IP options bytes (length must = (v4IHL-5)*4)

	// IPv6 fields
	v6PayloadLen int  // 0 = auto-fill
	v6NextHdr    byte // 0 + v6NextHdrSet=false → defaults to TCP
	v6NextHdrSet bool // explicit override so v6NextHdr=0 (HopByHop) is testable
	v6SrcIP      [16]byte
	v6DstIP      [16]byte

	// TCP
	tcpSrcPort uint16
	tcpDstPort uint16
	tcpSeq     uint32
	tcpAck     uint32
	tcpDataOff int  // words; 5 = 20 bytes (no options), 15 = 60 bytes
	tcpFlags   byte // raw byte-13 flags
	tcpOpts    []byte

	payload []byte

	// Optional Ethernet trailer padding (Ethernet minimum 60 bytes).
	ethPad int
}

func (rf *rawFrame) build() []byte {
	if rf.v4IHL == 0 {
		rf.v4IHL = 5
	}
	if rf.tcpDataOff == 0 {
		rf.tcpDataOff = 5
	}

	ipHdrSize := 0
	switch rf.ethType {
	case ethTypeIPv4:
		ipHdrSize = rf.v4IHL * 4
	case ethTypeIPv6:
		ipHdrSize = ipv6HdrSize
	}
	tcpHdrLen := rf.tcpDataOff * 4

	var buf []byte
	// Ethernet (14 bytes: 6 dst, 6 src, 2 ethType).
	buf = append(buf, make([]byte, 12)...)
	tmp := [2]byte{}
	binary.BigEndian.PutUint16(tmp[:], rf.ethType)
	buf = append(buf, tmp[:]...)

	switch rf.ethType {
	case ethTypeIPv4:
		// IPv4 header.
		ipStart := len(buf)
		buf = append(buf, make([]byte, ipHdrSize)...)
		ip := buf[ipStart:]
		ip[0] = byte(0x40 | (rf.v4IHL & 0x0F))
		ip[1] = 0
		totalLen := rf.v4TotalLen
		if totalLen == 0 {
			totalLen = ipHdrSize + tcpHdrLen + len(rf.payload)
		}
		binary.BigEndian.PutUint16(ip[2:4], uint16(totalLen))
		binary.BigEndian.PutUint16(ip[4:6], 0)             // Identification
		binary.BigEndian.PutUint16(ip[6:8], rf.v4FlagsFrag) // Flags + frag offset
		ip[8] = 64                                          // TTL
		proto := rf.v4Protocol
		if proto == 0 {
			proto = ipProtoTCP
		}
		ip[9] = proto
		binary.BigEndian.PutUint16(ip[10:12], 0) // checksum, leave 0 for tests
		copy(ip[12:16], rf.v4SrcIP[:])
		copy(ip[16:20], rf.v4DstIP[:])
		if len(rf.v4OptsPad) > 0 {
			copy(ip[20:], rf.v4OptsPad)
		}
	case ethTypeIPv6:
		ipStart := len(buf)
		buf = append(buf, make([]byte, ipv6HdrSize)...)
		ip := buf[ipStart:]
		ip[0] = 0x60 // Version=6, TC/FL=0
		payLen := rf.v6PayloadLen
		if payLen == 0 {
			payLen = tcpHdrLen + len(rf.payload)
		}
		binary.BigEndian.PutUint16(ip[4:6], uint16(payLen))
		next := rf.v6NextHdr
		if next == 0 && !rf.v6NextHdrSet {
			next = ipProtoTCP
		}
		ip[6] = next
		ip[7] = 64
		copy(ip[8:24], rf.v6SrcIP[:])
		copy(ip[24:40], rf.v6DstIP[:])
	}

	// TCP header.
	tcpStart := len(buf)
	buf = append(buf, make([]byte, tcpHdrLen)...)
	tcp := buf[tcpStart:]
	binary.BigEndian.PutUint16(tcp[0:2], rf.tcpSrcPort)
	binary.BigEndian.PutUint16(tcp[2:4], rf.tcpDstPort)
	binary.BigEndian.PutUint32(tcp[4:8], rf.tcpSeq)
	binary.BigEndian.PutUint32(tcp[8:12], rf.tcpAck)
	tcp[12] = byte(rf.tcpDataOff<<4) & 0xF0
	tcp[13] = rf.tcpFlags
	binary.BigEndian.PutUint16(tcp[14:16], 65535) // window
	if len(rf.tcpOpts) > 0 {
		copy(tcp[20:], rf.tcpOpts)
	}

	// Payload.
	buf = append(buf, rf.payload...)

	// Ethernet padding (raw zeros after the IP-declared body).
	if rf.ethPad > 0 {
		buf = append(buf, make([]byte, rf.ethPad)...)
	}
	return buf
}

func ipv4(a, b, c, d byte) [4]byte { return [4]byte{a, b, c, d} }

// --- IP options ------------------------------------------------------------

func TestParseInbound_IPv4_WithOptions(t *testing.T) {
	// IHL=10 → 40-byte IP header (20 bytes base + 20 bytes of options).
	// We just zero-fill the options; the parser shouldn't care about
	// their contents, only that it skips them correctly to find the TCP
	// header.
	payload := []byte("hello world")
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      10,
		v4FlagsFrag: 0x4000, // DF
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		v4OptsPad:  make([]byte, 20),
		tcpSrcPort: 5555,
		tcpDstPort: 80,
		tcpDataOff: 5,
		tcpFlags:   0x18, // PSH+ACK
		payload:    payload,
	}
	frame := rf.build()

	gotIP, gotPort, gotPayload, ok := parseInbound(frame)
	if !ok {
		t.Fatal("rejected unexpectedly")
	}
	if !net.IP(gotIP[:4]).Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("srcIP = %v want 10.0.0.1", net.IP(gotIP[:4]))
	}
	if gotPort != 5555 {
		t.Fatalf("srcPort = %d want 5555", gotPort)
	}
	if string(gotPayload) != "hello world" {
		t.Fatalf("payload = %q want %q", string(gotPayload), "hello world")
	}
}

func TestParseInbound_IPv4_MaxOptions(t *testing.T) {
	// IHL=15 → 60-byte IP header (the maximum).
	payload := []byte("ok")
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      15,
		v4FlagsFrag: 0x4000,
		v4SrcIP:    ipv4(1, 2, 3, 4),
		v4DstIP:    ipv4(5, 6, 7, 8),
		v4OptsPad:  make([]byte, 40),
		tcpSrcPort: 1234,
		tcpDstPort: 80,
		tcpDataOff: 5,
		tcpFlags:   0x10,
		payload:    payload,
	}
	frame := rf.build()
	_, port, p, ok := parseInbound(frame)
	if !ok || port != 1234 || string(p) != "ok" {
		t.Fatalf("ok=%v port=%d payload=%q", ok, port, string(p))
	}
}

// --- Fragmentation --------------------------------------------------------

func TestParseInbound_IPv4_NonZeroFragOffset(t *testing.T) {
	// Fragment offset != 0 — this is a continuation fragment, not a
	// first segment. The TCP header is NOT at the start of the IP body.
	// Must reject.
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x4000 | 0x0001, // DF + frag offset 1 (8 bytes)
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80,
		tcpDstPort: 80,
		payload:    make([]byte, 64),
	}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("non-zero fragment offset wrongly accepted")
	}
}

func TestParseInbound_IPv4_MoreFragmentsFlag(t *testing.T) {
	// MF=1, offset=0 — first fragment of a fragmented datagram. The TCP
	// header is at the start, but the payload is incomplete. Reject as
	// a defensive measure: paqet's senders set DF, so any MF we see is
	// either an attack or a misconfig.
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x2000, // MF
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80,
		tcpDstPort: 80,
		payload:    make([]byte, 64),
	}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("MF=1 wrongly accepted")
	}
}

func TestParseInbound_IPv4_ReservedFlagSet(t *testing.T) {
	// Reserved bit (0x8000) must be 0 per RFC. Some carrier middleboxes
	// have been observed setting it. Reject as anomalous.
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x8000, // reserved bit
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80,
		tcpDstPort: 80,
		payload:    make([]byte, 64),
	}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("reserved flag wrongly accepted")
	}
}

func TestParseInbound_IPv4_NoFlagsClean(t *testing.T) {
	// DF=0, MF=0, offset=0 — completely valid non-fragmented packet
	// that just happens to not set DF. Must accept.
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x0000,
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80,
		tcpDstPort: 80,
		payload:    []byte("ok"),
	}
	if _, _, p, ok := parseInbound(rf.build()); !ok || string(p) != "ok" {
		t.Fatalf("clean no-DF wrongly rejected: ok=%v p=%q", ok, p)
	}
}

// --- VLAN / unknown ethType -----------------------------------------------

func TestParseInbound_VLAN_Rejected(t *testing.T) {
	// 0x8100 is the ethType for IEEE 802.1Q VLAN tags. We don't unwrap
	// them. The frame should be silently dropped (caller continues to
	// the next packet).
	rf := &rawFrame{ethType: 0x8100, v4SrcIP: ipv4(1, 2, 3, 4), payload: []byte("x")}
	frame := rf.build()
	if _, _, _, ok := parseInbound(frame); ok {
		t.Fatal("VLAN frame wrongly accepted")
	}
}

func TestParseInbound_QinQ_Rejected(t *testing.T) {
	// 0x88a8 is the ethType for stacked / QinQ VLAN. Same handling.
	rf := &rawFrame{ethType: 0x88a8, v4SrcIP: ipv4(1, 2, 3, 4), payload: []byte("x")}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("QinQ frame wrongly accepted")
	}
}

func TestParseInbound_ARP_Rejected(t *testing.T) {
	rf := &rawFrame{ethType: 0x0806, payload: []byte("arp")}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("ARP frame wrongly accepted")
	}
}

// --- IPv6 extension headers ----------------------------------------------

func TestParseInbound_IPv6_HopByHop_Rejected(t *testing.T) {
	// NextHeader=0 means Hop-by-Hop options. paqet doesn't traverse
	// extension-header chains; reject to avoid mis-locating the TCP
	// header. (Real-world inbound to a paqet server should always be
	// NextHeader=TCP since the senders are paqet clients.)
	rf := &rawFrame{
		ethType:      ethTypeIPv6,
		v6NextHdr:    0, // Hop-by-Hop
		v6NextHdrSet: true,
		tcpSrcPort:   80, tcpDstPort: 80,
		payload: []byte("x"),
	}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("Hop-by-Hop next-header wrongly accepted")
	}
}

func TestParseInbound_IPv6_RoutingHeader_Rejected(t *testing.T) {
	// NextHeader=43 — Routing extension header.
	rf := &rawFrame{
		ethType:    ethTypeIPv6,
		v6NextHdr:  43,
		tcpSrcPort: 80, tcpDstPort: 80,
		payload: []byte("x"),
	}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("Routing extension header wrongly accepted")
	}
}

func TestParseInbound_IPv6_FragmentHeader_Rejected(t *testing.T) {
	// NextHeader=44 — IPv6 Fragment header. Same reasoning as IPv4
	// fragmentation rejection.
	rf := &rawFrame{
		ethType:    ethTypeIPv6,
		v6NextHdr:  44,
		tcpSrcPort: 80, tcpDstPort: 80,
		payload: []byte("x"),
	}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("IPv6 Fragment extension header wrongly accepted")
	}
}

// --- TCP header sizes ----------------------------------------------------

func TestParseInbound_TCP_MaxDataOffset(t *testing.T) {
	// dataOff=15 → 60-byte TCP header, the maximum the spec allows.
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x4000,
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 12345,
		tcpDstPort: 80,
		tcpDataOff: 15,
		tcpOpts:    make([]byte, 40), // 40 bytes of options
		payload:    []byte("late"),
	}
	_, port, p, ok := parseInbound(rf.build())
	if !ok || port != 12345 || string(p) != "late" {
		t.Fatalf("max-dataOff parse failed: ok=%v port=%d p=%q", ok, port, p)
	}
}

func TestParseInbound_TCP_DataOffTooSmall(t *testing.T) {
	// dataOff < 5 is illegal — the base TCP header is 20 bytes.
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x4000,
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80, tcpDstPort: 80,
		tcpDataOff: 4,
	}
	frame := rf.build()
	// rf.build allocates tcpDataOff*4 bytes for the header; with dataOff=4
	// we get a 16-byte short TCP, which itself is below tcpHdrSize. The
	// parser should reject either at the dataOff<5 check or at the
	// short-header check — both are valid.
	if _, _, _, ok := parseInbound(frame); ok {
		t.Fatal("dataOff<5 wrongly accepted")
	}
}

func TestParseInbound_TCP_DataOffPastDeclaredLength(t *testing.T) {
	// dataOff claims more TCP header bytes than IP totalLen leaves
	// available. Must reject.
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x4000,
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		v4TotalLen: 20 + 20, // IP + base TCP only, no room for options
		tcpSrcPort: 80, tcpDstPort: 80,
		tcpDataOff: 10, // claims 40 bytes of TCP header
		tcpOpts:    make([]byte, 20),
	}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("dataOff overrun wrongly accepted")
	}
}

// --- Length / size edge cases --------------------------------------------

func TestParseInbound_IPv4_TotalLenSmallerThanHeader(t *testing.T) {
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x4000,
		v4TotalLen: 10, // less than 20-byte minimum IP header
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80, tcpDstPort: 80,
	}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("totalLen < ipHdrLen wrongly accepted")
	}
}

func TestParseInbound_IPv4_TotalLenZero(t *testing.T) {
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x4000,
		v4TotalLen: 0xffff, // not 0 — we can't actually set 0 because v4TotalLen=0 means auto-fill. Use max.
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80, tcpDstPort: 80,
		payload: make([]byte, 100),
	}
	// IP claims 65535 bytes total but the buffer is much smaller. Reject.
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("oversized totalLen wrongly accepted")
	}
}

// --- Jumbo / large payload -----------------------------------------------

func TestParseInbound_IPv4_JumboFrame(t *testing.T) {
	// 9000-byte payload. Real ethernet hardware has a 1500-byte MTU
	// default, but jumbo-frame networks go up to 9000. paqet's pcap
	// receive path can see arbitrarily-large captures depending on
	// snaplen (we set 65536); parser must not impose its own cap.
	payload := make([]byte, 9000)
	for i := range payload {
		payload[i] = byte(i)
	}
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x4000,
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80, tcpDstPort: 80,
		payload: payload,
	}
	_, _, p, ok := parseInbound(rf.build())
	if !ok {
		t.Fatal("jumbo frame wrongly rejected")
	}
	if len(p) != 9000 {
		t.Fatalf("payload size = %d want 9000", len(p))
	}
	if p[0] != 0 || p[1] != 1 || p[8999] != byte(8999&0xFF) {
		t.Fatal("payload contents corrupted")
	}
}

func TestParseInbound_IPv6_JumboFrame(t *testing.T) {
	payload := make([]byte, 9000)
	for i := range payload {
		payload[i] = byte(i)
	}
	rf := &rawFrame{
		ethType:    ethTypeIPv6,
		tcpSrcPort: 80, tcpDstPort: 80,
		payload: payload,
	}
	_, _, p, ok := parseInbound(rf.build())
	if !ok || len(p) != 9000 {
		t.Fatalf("IPv6 jumbo: ok=%v len=%d", ok, len(p))
	}
}

// --- Ethernet padding ----------------------------------------------------

func TestParseInbound_EthernetPaddingTrailer(t *testing.T) {
	// Real NICs pad short frames to the 60-byte Ethernet minimum (64
	// with FCS, but pcap strips FCS). The trailing zeros are NOT part
	// of the IP payload; the parser must use the IP totalLen (or IPv6
	// PayloadLength) to truncate.
	payload := []byte("hi")
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x4000,
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80, tcpDstPort: 80,
		payload: payload,
		ethPad:  20, // 20 bytes of zero padding after the IP body
	}
	frame := rf.build()
	_, _, p, ok := parseInbound(frame)
	if !ok {
		t.Fatal("padded frame wrongly rejected")
	}
	if string(p) != "hi" {
		t.Fatalf("padding leaked into payload: got %q (len=%d)", p, len(p))
	}
}

// --- Non-TCP protocol ---------------------------------------------------

func TestParseInbound_IPv4_UDPRejected(t *testing.T) {
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x4000,
		v4Protocol: 17, // UDP
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80, tcpDstPort: 80, // UDP-as-TCP payload, parser shouldn't reach
	}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("UDP protocol wrongly accepted")
	}
}

func TestParseInbound_IPv4_ICMPRejected(t *testing.T) {
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x4000,
		v4Protocol: 1, // ICMP
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80, tcpDstPort: 80,
	}
	if _, _, _, ok := parseInbound(rf.build()); ok {
		t.Fatal("ICMP protocol wrongly accepted")
	}
}

// --- Version field ------------------------------------------------------

func TestParseInbound_IPv4_WrongVersion(t *testing.T) {
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4IHL:      5,
		v4FlagsFrag: 0x4000,
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 80, tcpDstPort: 80,
	}
	frame := rf.build()
	// Corrupt the IP version: byte after ethernet[12:14], byte[0] high nibble.
	frame[ethHdrSize] = 0x55 // version=5, IHL=5
	if _, _, _, ok := parseInbound(frame); ok {
		t.Fatal("IP version=5 wrongly accepted")
	}
}

func TestParseInbound_IPv6_WrongVersion(t *testing.T) {
	rf := &rawFrame{
		ethType:    ethTypeIPv6,
		tcpSrcPort: 80, tcpDstPort: 80,
	}
	frame := rf.build()
	frame[ethHdrSize] = 0x80 // version=8
	if _, _, _, ok := parseInbound(frame); ok {
		t.Fatal("IPv6 version=8 wrongly accepted")
	}
}
