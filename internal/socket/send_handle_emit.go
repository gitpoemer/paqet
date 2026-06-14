package socket

// Hand-rolled outbound packet serialization. Replaces gopacket's
// interface-driven SerializeLayers + ComputeChecksums in the hot path.
//
// We can't avoid recomputing the TCP checksum (it covers the payload, which
// changes per packet). What we CAN avoid is gopacket's per-call interface
// dispatch, layer-system bookkeeping, and the SerializeBuffer's prepend-from-
// back internal allocator. Direct byte writes against a single scratch
// buffer cut ~20-30% of the outbound CPU budget on this path.
//
// Stealth: byte-for-byte identical to the gopacket output (verified by
// TestSerializeEquivalence). No on-wire change.
//
// Layout we emit (IPv4 case):
//
//   eth (14) | ip4 (20) | tcp_hdr (20) | tcp_opts (12 or 20) | payload (N)
//
// IPv6 case substitutes a 40-byte IPv6 header; payload length lands in
// IPv6.PayloadLength (which excludes the IPv6 header) instead of
// IPv4.TotalLength (which includes it).

import (
	"encoding/binary"
	"net"
	"paqet/internal/conf"
)

// packetFields captures the volatile state per outbound packet, factored
// out so the serialize function is pure and testable without atomic
// counters or pool allocations interfering.
type packetFields struct {
	dstIP   net.IP
	dstPort uint16
	flags   conf.TCPF
	seq     uint32
	ack     uint32
	tsVal   uint32
	tsEcr   uint32 // 0 on SYN
	// ipID is the 16-bit IPv4 Identification value. Real stacks pick
	// varying values (per-packet or per-flow); always emitting 0 (the
	// alpha.23 behavior, matching gopacket's default) is a clean
	// fingerprint. Set in nextPacketFields via a hash of the per-handle
	// counter. Ignored for IPv6.
	ipID uint16
}

// Wire constants. Match the values gopacket emits for the equivalent
// layers under the configuration we use elsewhere.
const (
	ethTypeIPv4 uint16 = 0x0800
	ethTypeIPv6 uint16 = 0x86DD

	ipProtoTCP byte = 6

	// MSS option value 1460 = 0x05B4 — matches buildTCPHeader.
	tcpMSSValue uint16 = 1460
	// Window scale of 8 — matches buildTCPHeader.
	tcpWindowScale byte = 8
	// Receive window — matches buildTCPHeader.
	tcpWindow uint16 = 65535

	// Header sizes in bytes.
	ethHdrSize  = 14
	ipv4HdrSize = 20
	ipv6HdrSize = 40
	tcpHdrSize  = 20 // base header, options follow
	// SYN options: MSS(4) + SACK(2) + TS(10) + NOP(1) + WScale(3) = 20.
	tcpOptsSize_SYN    = 20
	tcpHdrPlusOpts_SYN = tcpHdrSize + tcpOptsSize_SYN
	// non-SYN options: NOP(1) + NOP(1) + TS(10) = 12.
	tcpOptsSize_NoSYN    = 12
	tcpHdrPlusOpts_NoSYN = tcpHdrSize + tcpOptsSize_NoSYN

	// Default IP TOS (DSCP 46 = EF) — matches buildIPv4Header/buildIPv6Header.
	ipTOS_TC = 184
	ipTTL    = 64
)

// flagBits returns the byte that goes into the TCP flags slot at byte 13 of
// the TCP header. Bit layout per RFC 793 + later extensions:
//   bit 7: CWR
//   bit 6: ECE
//   bit 5: URG
//   bit 4: ACK
//   bit 3: PSH
//   bit 2: RST
//   bit 1: SYN
//   bit 0: FIN
// NS lives one bit further up (in the reserved nibble at byte 12 low bit).
func flagBits(f conf.TCPF) byte {
	var b byte
	if f.FIN {
		b |= 0x01
	}
	if f.SYN {
		b |= 0x02
	}
	if f.RST {
		b |= 0x04
	}
	if f.PSH {
		b |= 0x08
	}
	if f.ACK {
		b |= 0x10
	}
	if f.URG {
		b |= 0x20
	}
	if f.ECE {
		b |= 0x40
	}
	if f.CWR {
		b |= 0x80
	}
	return b
}

// serializePacketTo writes the full eth+ip+tcp+payload packet into the
// caller-supplied scratch slice. The slice must be at least
// scratchSizeFor(payload, isIPv6) bytes long. Returns the number of bytes
// written.
//
// The caller selects scratch sizing via maxPacketSize() to avoid bounds
// checks on the hot path.
func (h *SendHandle) serializePacketTo(scratch, payload []byte, pf packetFields) int {
	if pf.dstIP.To4() != nil {
		return h.serializeIPv4(scratch, payload, pf)
	}
	return h.serializeIPv6(scratch, payload, pf)
}

func (h *SendHandle) serializeIPv4(scratch, payload []byte, pf packetFields) int {
	srcIP4 := h.srcIPv4.To4()
	dstIP4 := pf.dstIP.To4()

	// TCP header size depends on whether this is a SYN (longer options).
	tcpTotal := tcpHdrPlusOpts_NoSYN
	if pf.flags.SYN {
		tcpTotal = tcpHdrPlusOpts_SYN
	}
	ipTotal := ipv4HdrSize + tcpTotal + len(payload)
	total := ethHdrSize + ipTotal

	// ----- Ethernet -----
	copy(scratch[0:6], h.srcIPv4RHWA) // DstMAC = gateway HW addr
	copy(scratch[6:12], h.srcMAC())   // SrcMAC
	binary.BigEndian.PutUint16(scratch[12:14], ethTypeIPv4)

	// ----- IPv4 -----
	ip := scratch[ethHdrSize:]
	ip[0] = 0x45                                       // Version (4) + IHL (5 words = 20 bytes)
	ip[1] = ipTOS_TC                                   // DSCP/ECN
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipTotal)) // TotalLength
	binary.BigEndian.PutUint16(ip[4:6], pf.ipID)         // Identification (varies per packet)
	binary.BigEndian.PutUint16(ip[6:8], 0x4000)        // Flags=DF, FragmentOffset=0
	ip[8] = ipTTL                                      // TTL
	ip[9] = ipProtoTCP                                 // Protocol
	binary.BigEndian.PutUint16(ip[10:12], 0)           // Checksum placeholder
	copy(ip[12:16], srcIP4)
	copy(ip[16:20], dstIP4)
	// IP header checksum over the 20-byte IPv4 header.
	binary.BigEndian.PutUint16(ip[10:12], onesComplementChecksum(ip[0:20], 0))

	// ----- TCP -----
	tcp := scratch[ethHdrSize+ipv4HdrSize:]
	h.writeTCPHeaderAndOptions(tcp, pf, tcpTotal)
	copy(tcp[tcpTotal:], payload)

	// TCP checksum: pseudo-header + TCP header + payload, with checksum
	// field zeroed (we set it to 0 above implicitly).
	pseudoSum := pseudoHeaderIPv4Sum(srcIP4, dstIP4, uint16(tcpTotal+len(payload)))
	binary.BigEndian.PutUint16(tcp[16:18], onesComplementChecksum(tcp[:tcpTotal+len(payload)], pseudoSum))

	return total
}

func (h *SendHandle) serializeIPv6(scratch, payload []byte, pf packetFields) int {
	tcpTotal := tcpHdrPlusOpts_NoSYN
	if pf.flags.SYN {
		tcpTotal = tcpHdrPlusOpts_SYN
	}
	payloadLen := tcpTotal + len(payload) // IPv6 PayloadLength excludes IPv6 header

	// ----- Ethernet -----
	copy(scratch[0:6], h.srcIPv6RHWA)
	copy(scratch[6:12], h.srcMAC())
	binary.BigEndian.PutUint16(scratch[12:14], ethTypeIPv6)

	// ----- IPv6 -----
	ip := scratch[ethHdrSize:]
	// Version(4) | TrafficClass(8) | FlowLabel(20)
	// TC = 184 -> top 4 bits of TC into byte 0 low nibble (0xB), bottom 4 bits into byte 1 high nibble (0x8).
	ip[0] = 0x60 | (ipTOS_TC >> 4)            // 0x60 = Version 6
	ip[1] = byte((ipTOS_TC&0x0F)<<4) | 0      // FlowLabel high 4 bits = 0
	ip[2] = 0                                  // FlowLabel mid 8 bits = 0
	ip[3] = 0                                  // FlowLabel low 8 bits = 0
	binary.BigEndian.PutUint16(ip[4:6], uint16(payloadLen))
	ip[6] = ipProtoTCP // NextHeader
	ip[7] = ipTTL      // HopLimit
	copy(ip[8:24], h.srcIPv6.To16())
	copy(ip[24:40], pf.dstIP.To16())

	// ----- TCP -----
	tcp := scratch[ethHdrSize+ipv6HdrSize:]
	h.writeTCPHeaderAndOptions(tcp, pf, tcpTotal)
	copy(tcp[tcpTotal:], payload)

	pseudoSum := pseudoHeaderIPv6Sum(h.srcIPv6.To16(), pf.dstIP.To16(), uint32(tcpTotal+len(payload)))
	binary.BigEndian.PutUint16(tcp[16:18], onesComplementChecksum(tcp[:tcpTotal+len(payload)], pseudoSum))

	return ethHdrSize + ipv6HdrSize + payloadLen
}

// writeTCPHeaderAndOptions writes the 20-byte TCP header followed by the
// options block (12 or 20 bytes). Leaves TCP checksum at 0 for the caller
// to fill in.
func (h *SendHandle) writeTCPHeaderAndOptions(tcp []byte, pf packetFields, tcpTotal int) {
	binary.BigEndian.PutUint16(tcp[0:2], h.srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], pf.dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], pf.seq)
	binary.BigEndian.PutUint32(tcp[8:12], pf.ack)
	// Byte 12: DataOffset (high nibble = words including options) | reserved low nibble (with NS bit)
	dataOff := byte(tcpTotal/4) << 4
	if pf.flags.NS {
		dataOff |= 0x01
	}
	tcp[12] = dataOff
	tcp[13] = flagBits(pf.flags)
	binary.BigEndian.PutUint16(tcp[14:16], tcpWindow)
	binary.BigEndian.PutUint16(tcp[16:18], 0) // Checksum (filled later)
	binary.BigEndian.PutUint16(tcp[18:20], 0) // UrgentPointer

	// Options. Layouts mirror buildTCPHeader exactly.
	opts := tcp[20:tcpTotal]
	if pf.flags.SYN {
		// MSS (kind=2, len=4, value=1460)
		opts[0] = 2
		opts[1] = 4
		binary.BigEndian.PutUint16(opts[2:4], tcpMSSValue)
		// SACK Permitted (kind=4, len=2)
		opts[4] = 4
		opts[5] = 2
		// Timestamps (kind=8, len=10, val=tsVal, ecr=0 on SYN)
		opts[6] = 8
		opts[7] = 10
		binary.BigEndian.PutUint32(opts[8:12], pf.tsVal)
		binary.BigEndian.PutUint32(opts[12:16], 0)
		// NOP
		opts[16] = 1
		// Window Scale (kind=3, len=3, shift=8)
		opts[17] = 3
		opts[18] = 3
		opts[19] = tcpWindowScale
	} else {
		// NOP, NOP, Timestamps (kind=8, len=10, val=tsVal, ecr=tsEcr)
		opts[0] = 1
		opts[1] = 1
		opts[2] = 8
		opts[3] = 10
		binary.BigEndian.PutUint32(opts[4:8], pf.tsVal)
		binary.BigEndian.PutUint32(opts[8:12], pf.tsEcr)
	}
}

// srcMAC returns the configured outbound MAC. SendHandle snapshots this
// in cfgInterfaceMAC at construction.
func (h *SendHandle) srcMAC() []byte {
	return h.cfgInterfaceMAC
}

// onesComplementChecksum implements the standard internet checksum.
// `initial` is folded in to allow callers to feed a pre-summed
// pseudo-header without copying it into the data buffer.
func onesComplementChecksum(data []byte, initial uint32) uint16 {
	sum := initial
	i := 0
	for ; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if i < len(data) {
		sum += uint32(data[i]) << 8
	}
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// pseudoHeaderIPv4Sum returns the partial 32-bit sum of the IPv4 TCP
// pseudo-header. The full checksum function folds this in via `initial`.
//
// Pseudo-header layout (12 bytes):
//   srcIP (4) | dstIP (4) | zero (1) | protocol (1) | tcpLength (2)
func pseudoHeaderIPv4Sum(src, dst net.IP, tcpLen uint16) uint32 {
	var sum uint32
	sum += uint32(src[0])<<8 | uint32(src[1])
	sum += uint32(src[2])<<8 | uint32(src[3])
	sum += uint32(dst[0])<<8 | uint32(dst[1])
	sum += uint32(dst[2])<<8 | uint32(dst[3])
	sum += uint32(ipProtoTCP) // zero byte + protocol byte
	sum += uint32(tcpLen)
	return sum
}

// pseudoHeaderIPv6Sum returns the partial 32-bit sum of the IPv6 TCP
// pseudo-header.
//
// IPv6 pseudo-header layout (40 bytes):
//   srcIP (16) | dstIP (16) | length (4) | zero (3) | nextHeader (1)
func pseudoHeaderIPv6Sum(src, dst net.IP, tcpLen uint32) uint32 {
	var sum uint32
	for i := 0; i < 16; i += 2 {
		sum += uint32(src[i])<<8 | uint32(src[i+1])
	}
	for i := 0; i < 16; i += 2 {
		sum += uint32(dst[i])<<8 | uint32(dst[i+1])
	}
	sum += tcpLen & 0xFFFF
	sum += tcpLen >> 16
	sum += uint32(ipProtoTCP)
	return sum
}

// maxPacketSize returns an upper bound on bytes we'll emit for a given
// payload length. Callers size their scratch buffer with this.
func maxPacketSize(payloadLen int) int {
	return ethHdrSize + ipv6HdrSize + tcpHdrPlusOpts_SYN + payloadLen
}
