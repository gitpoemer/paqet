package socket

import (
	"encoding/binary"
	"net"
	"paqet/internal/conf"
	"sync"
	"testing"
)

// TestParseInbound_TimestampExtraction verifies that the TCP timestamp
// option (kind=8) is correctly extracted from inbound segments, since
// that value drives the per-flow tsEcr we emit on outbound traffic.
func TestParseInbound_TimestampExtraction(t *testing.T) {
	h := mkTestHandle()
	pf := packetFields{
		dstIP:   net.IPv4(192, 168, 1, 100),
		dstPort: 443,
		flags:   conf.TCPF{PSH: true, ACK: true},
		seq:     1, ack: 1,
		tsVal: 0xCAFEBABE, // sender's tsVal becomes peer's tsVal at recv side
		tsEcr: 0x11223344,
		ipID:  0xABCD,
	}
	frame := buildSyntheticFrame(t, h, []byte("ts-test"), pf)

	_, _, peerTsVal, _, ok := parseInbound(frame)
	if !ok {
		t.Fatal("parseInbound rejected a well-formed frame")
	}
	if peerTsVal != 0xCAFEBABE {
		t.Fatalf("peerTsVal = %#x want %#x", peerTsVal, 0xCAFEBABE)
	}
}

// TestParseInbound_TimestampExtraction_SYN: SYN segments use a different
// option ordering (MSS, SACK, TS, NOP, WS). The timestamp option still
// has to be found by the option-walker.
func TestParseInbound_TimestampExtraction_SYN(t *testing.T) {
	h := mkTestHandle()
	pf := packetFields{
		dstIP:   net.IPv4(192, 168, 1, 100),
		dstPort: 443,
		flags:   conf.TCPF{SYN: true},
		seq:     1, ack: 0,
		tsVal: 0xDEADBEEF,
		ipID:  0x1234,
	}
	frame := buildSyntheticFrame(t, h, nil, pf)

	_, _, peerTsVal, _, ok := parseInbound(frame)
	if !ok {
		t.Fatal("SYN frame rejected")
	}
	if peerTsVal != 0xDEADBEEF {
		t.Fatalf("SYN peerTsVal = %#x want %#x", peerTsVal, 0xDEADBEEF)
	}
}

// TestParseInbound_NoTimestampOption: when the peer doesn't include the
// timestamp option, peerTsVal must be 0 so the sender knows to fall back
// to the synthetic value.
func TestParseInbound_NoTimestampOption(t *testing.T) {
	// Build a TCP frame with no options at all (dataOff=5).
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4FlagsFrag: 0x4000,
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 1234, tcpDstPort: 80,
		tcpDataOff: 5, // no options
		tcpFlags:   0x18,
		payload:    []byte("plain"),
	}
	_, _, peerTsVal, _, ok := parseInbound(rf.build())
	if !ok {
		t.Fatal("no-options frame rejected")
	}
	if peerTsVal != 0 {
		t.Fatalf("expected peerTsVal=0 for option-less frame, got %#x", peerTsVal)
	}
}

// TestParseInbound_MalformedOption_DoesNotPanic: an option with a
// nonsense length must abort the option walk cleanly, not OOB-read.
func TestParseInbound_MalformedOption_DoesNotPanic(t *testing.T) {
	// Build a frame with dataOff=8 (32 bytes of TCP) and stuff the
	// options with a fake option claiming olen=255 (well beyond
	// the options area).
	opts := make([]byte, 12)
	opts[0] = 8           // kind=8 (Timestamps)
	opts[1] = 255         // bogus length
	rf := &rawFrame{
		ethType:    ethTypeIPv4,
		v4FlagsFrag: 0x4000,
		v4SrcIP:    ipv4(10, 0, 0, 1),
		v4DstIP:    ipv4(10, 0, 0, 2),
		tcpSrcPort: 1, tcpDstPort: 1,
		tcpDataOff: 8,
		tcpOpts:    opts,
		payload:    []byte("x"),
	}
	// Must not panic; ok must still be true (the frame itself is
	// structurally valid, just the option scan exits without finding TS).
	_, _, peerTsVal, _, ok := parseInbound(rf.build())
	if !ok {
		t.Fatal("structurally valid frame rejected")
	}
	if peerTsVal != 0 {
		t.Fatalf("malformed option should yield peerTsVal=0, got %#x", peerTsVal)
	}
}

// TestRecordPeerTSVal_EchoedInTsEcr: end-to-end verification that a peer
// tsVal recorded on the recv side appears as tsEcr on the next outbound
// segment to the same peer.
func TestRecordPeerTSVal_EchoedInTsEcr(t *testing.T) {
	sh := mkTestHandle()
	// Fully initialize TCPF — nextPacketFields calls getClientTCPF.
	sh.tcpF.tcpF.Items = []conf.TCPF{{PSH: true, ACK: true}}

	dstIP := net.IPv4(192, 168, 1, 50)
	const dstPort uint16 = 5000
	const peerTS uint32 = 0xFEEDC0DE

	sh.recordPeerTSVal(dstIP, dstPort, peerTS)
	pf := sh.nextPacketFields(dstIP, dstPort)
	if pf.flags.SYN {
		t.Fatal("test setup wrong: expected non-SYN flag set")
	}
	if pf.tsEcr != peerTS {
		t.Fatalf("tsEcr = %#x want %#x (peer's recorded tsVal)", pf.tsEcr, peerTS)
	}
}

// TestRecordPeerTSVal_SYNStillsEmitsZeroTsEcr: SYN segments must keep
// tsEcr=0 regardless of any cached peer timestamp, since the TCP spec
// says the SYN's tsEcr field is meaningless.
func TestRecordPeerTSVal_SYNStillEmitsZeroTsEcr(t *testing.T) {
	sh := mkTestHandle()
	sh.tcpF.tcpF.Items = []conf.TCPF{{SYN: true}}
	dstIP := net.IPv4(192, 168, 1, 51)
	sh.recordPeerTSVal(dstIP, 6000, 0x12345678)
	pf := sh.nextPacketFields(dstIP, 6000)
	if !pf.flags.SYN {
		t.Fatal("test setup wrong: expected SYN flag")
	}
	if pf.tsEcr != 0 {
		t.Fatalf("SYN tsEcr should be 0, got %#x", pf.tsEcr)
	}
}

// TestRecordPeerTSVal_NoPeerStateFallsBackToSynthetic: nextPacketFields
// must still emit some tsEcr when no peer state is recorded — otherwise
// the very first paqet client→server reply would emit tsEcr=0, which
// itself would be a fingerprint.
func TestRecordPeerTSVal_NoPeerStateFallsBackToSynthetic(t *testing.T) {
	sh := mkTestHandle()
	sh.tcpF.tcpF.Items = []conf.TCPF{{PSH: true, ACK: true}}
	pf := sh.nextPacketFields(net.IPv4(10, 0, 0, 99), 9999)
	if pf.flags.SYN {
		t.Fatal("test setup wrong")
	}
	if pf.tsEcr == 0 {
		t.Fatal("uninitialized peer state must NOT yield tsEcr=0 — that itself is a fingerprint")
	}
}

// TestRecordPeerTSVal_ZeroPeerTSIgnored: recording tsVal=0 (the "no
// timestamp option present" sentinel) must NOT overwrite a previously
// stored real value.
func TestRecordPeerTSVal_ZeroPeerTSIgnored(t *testing.T) {
	sh := mkTestHandle()
	dst := net.IPv4(10, 0, 0, 200)
	sh.recordPeerTSVal(dst, 1234, 0xABCDEF01)
	sh.recordPeerTSVal(dst, 1234, 0) // simulate a no-TS-option segment
	if got := sh.loadPeerTSVal(dst, 1234); got != 0xABCDEF01 {
		t.Fatalf("zero tsVal wrongly overwrote real value: got %#x", got)
	}
}

// TestRecordPeerTSVal_ConcurrentWriters: stress the LoadOrStore path
// under contention. Many goroutines storing the same key — exactly one
// should win the slot, all others reuse it.
func TestRecordPeerTSVal_ConcurrentWriters(t *testing.T) {
	sh := mkTestHandle()
	dst := net.IPv4(10, 0, 0, 7)
	const port uint16 = 555
	const N = 64
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(v uint32) {
			defer wg.Done()
			sh.recordPeerTSVal(dst, port, v)
		}(uint32(i + 1))
	}
	wg.Wait()
	got := sh.loadPeerTSVal(dst, port)
	if got == 0 || got > N {
		t.Fatalf("expected stored tsVal in [1,%d], got %#x", N, got)
	}
}

// TestIPIdentification_VariesPerPacket: emitter must produce different
// IP IDs across consecutive outbound packets, not constant 0 (the old
// behavior that was a clean fingerprint).
func TestIPIdentification_VariesPerPacket(t *testing.T) {
	sh := mkTestHandle()
	sh.tcpF.tcpF.Items = []conf.TCPF{{PSH: true, ACK: true}}
	dst := net.IPv4(10, 0, 0, 50)

	seen := make(map[uint16]int, 256)
	scratch := make([]byte, maxPacketSize(64))
	payload := make([]byte, 64)
	for i := 0; i < 256; i++ {
		pf := sh.nextPacketFields(dst, 80)
		n := sh.serializePacketTo(scratch, payload, pf)
		if n < ethHdrSize+ipv4HdrSize {
			t.Fatalf("serialized too few bytes: %d", n)
		}
		id := binary.BigEndian.Uint16(scratch[ethHdrSize+4 : ethHdrSize+6])
		seen[id]++
	}
	if _, allZero := seen[0]; allZero && len(seen) == 1 {
		t.Fatal("all 256 packets had IP Identification=0 (old fingerprintable behavior)")
	}
	if len(seen) < 200 {
		// Expect ~256 distinct values; Knuth multiplicative hash should
		// give near-zero collision rate over 256 inputs.
		t.Fatalf("expected high IP ID distinctness over 256 packets, only %d distinct", len(seen))
	}
}

// BenchmarkNextPacketFields_PeerTSCached times the cost of nextPacketFields
// when a peer tsVal is already cached — the steady-state condition.
func BenchmarkNextPacketFields_PeerTSCached(b *testing.B) {
	sh := mkTestHandle()
	sh.tcpF.tcpF.Items = []conf.TCPF{{PSH: true, ACK: true}}
	dst := net.IPv4(10, 0, 0, 1)
	sh.recordPeerTSVal(dst, 80, 0xABCDABCD)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sh.nextPacketFields(dst, 80)
	}
}

// BenchmarkNextPacketFields_PeerTSMiss times nextPacketFields when there's
// no cached peer tsVal (sync.Map miss path).
func BenchmarkNextPacketFields_PeerTSMiss(b *testing.B) {
	sh := mkTestHandle()
	sh.tcpF.tcpF.Items = []conf.TCPF{{PSH: true, ACK: true}}
	dst := net.IPv4(10, 0, 0, 1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sh.nextPacketFields(dst, 80)
	}
}
