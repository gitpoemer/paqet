package socket

// Hand-rolled inbound packet parser. Mirror image of send_handle_emit.go.
//
// Replaces gopacket.NewPacket(data, LayerTypeEthernet, NoCopy) and the
// layer.NetworkLayer() / .TransportLayer() / .ApplicationLayer() walks
// with a direct byte parse. Avoids gopacket's allocation of a *Packet
// struct plus per-layer interface dispatch per inbound packet.
//
// Returns:
//   - srcIP     — slice into `data` (do NOT retain past the next ReadPacketData)
//   - srcPort   — TCP source port
//   - peerTsVal — peer's TCP timestamp (option kind=8); 0 if absent
//   - payload   — slice into `data` (same retention constraint)
//   - ok        — false on any malformed/short/unsupported frame; caller
//                 should continue to the next packet, NOT surface as an error.
//
// Stealth: parser-only. No wire bytes change.

import (
	"encoding/binary"
)

// parseInbound decodes one ethernet/IP/TCP frame. Caller must ensure the
// caller holds `data` stable until they're done with the returned slices.
func parseInbound(data []byte) (srcIP []byte, srcPort uint16, peerTsVal uint32, payload []byte, ok bool) {
	if len(data) < ethHdrSize+ipv4HdrSize+tcpHdrSize {
		return nil, 0, 0, nil, false
	}

	// Ethernet type at [12:14].
	ethType := binary.BigEndian.Uint16(data[12:14])

	switch ethType {
	case ethTypeIPv4:
		return parseInboundIPv4(data)
	case ethTypeIPv6:
		return parseInboundIPv6(data)
	default:
		// 802.1Q VLAN tag (0x8100) or anything we don't handle. The BPF
		// filter restricts to TCP-over-IP so we shouldn't normally see
		// these, but be defensive.
		return nil, 0, 0, nil, false
	}
}

func parseInboundIPv4(data []byte) (srcIP []byte, srcPort uint16, peerTsVal uint32, payload []byte, ok bool) {
	ip := data[ethHdrSize:]
	if len(ip) < ipv4HdrSize {
		return nil, 0, 0, nil, false
	}

	// Version (high nibble of byte 0) must be 4. IHL (low nibble) is the
	// number of 32-bit words in the IP header; 5 = no options (20 bytes).
	verIhl := ip[0]
	if verIhl>>4 != 4 {
		return nil, 0, 0, nil, false
	}
	ihlWords := int(verIhl & 0x0F)
	if ihlWords < 5 {
		return nil, 0, 0, nil, false
	}
	ipHdrLen := ihlWords * 4
	if len(ip) < ipHdrLen {
		return nil, 0, 0, nil, false
	}

	// Protocol must be TCP.
	if ip[9] != ipProtoTCP {
		return nil, 0, 0, nil, false
	}

	// Reject fragments. Bytes [6:8] pack:
	//   bit 15 = reserved (must be 0)
	//   bit 14 = DF (may be 0 or 1; we don't care)
	//   bit 13 = MF
	//   bits 0-12 = fragment offset
	//
	// A safe-to-parse packet has MF=0 AND offset=0 AND reserved=0. That
	// is, the only bit we tolerate set is DF (0x4000). Any other set bit
	// means either an unsafe fragment or a malformed/attacker-shaped
	// header; either way, drop.
	//
	// The BPF filter normally prevents non-first fragments from reaching
	// us at all, but defense-in-depth: don't trust the filter to do
	// fragmentation-specific reasoning.
	if (binary.BigEndian.Uint16(ip[6:8]) & 0xBFFF) != 0 {
		return nil, 0, 0, nil, false
	}

	// Total length includes IP header + TCP header + payload.
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ipHdrLen {
		return nil, 0, 0, nil, false
	}
	// Some drivers add trailing padding to bring the frame to the minimum
	// 64-byte Ethernet size; truncate to the IP-declared length.
	if totalLen > len(ip) {
		// IP declares more bytes than we received — runt frame.
		return nil, 0, 0, nil, false
	}

	srcIP = ip[12:16]
	tcp := ip[ipHdrLen:totalLen]
	return finishTCPParse(tcp, srcIP)
}

func parseInboundIPv6(data []byte) (srcIP []byte, srcPort uint16, peerTsVal uint32, payload []byte, ok bool) {
	if len(data) < ethHdrSize+ipv6HdrSize+tcpHdrSize {
		return nil, 0, 0, nil, false
	}
	ip := data[ethHdrSize:]
	// Version is the high nibble of byte 0.
	if ip[0]>>4 != 6 {
		return nil, 0, 0, nil, false
	}

	// NextHeader at byte 6. For TCP without extension headers it's 6.
	// We don't traverse extension-header chains — paqet's own traffic
	// doesn't use them, and a peer sending them just gets dropped here.
	if ip[6] != ipProtoTCP {
		return nil, 0, 0, nil, false
	}

	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if payloadLen < tcpHdrSize {
		return nil, 0, 0, nil, false
	}
	if ipv6HdrSize+payloadLen > len(ip) {
		return nil, 0, 0, nil, false
	}

	srcIP = ip[8:24]
	tcp := ip[ipv6HdrSize : ipv6HdrSize+payloadLen]
	return finishTCPParse(tcp, srcIP)
}

// finishTCPParse extracts (srcPort, peerTsVal, payload) from a TCP segment
// whose bounds have already been validated as in-range of the underlying
// buffer. peerTsVal is the value of the TCP Timestamp option (kind=8) if
// present; 0 otherwise.
func finishTCPParse(tcp, srcIP []byte) ([]byte, uint16, uint32, []byte, bool) {
	if len(tcp) < tcpHdrSize {
		return nil, 0, 0, nil, false
	}
	srcPort := binary.BigEndian.Uint16(tcp[0:2])

	// Data offset: high nibble of byte 12, in 32-bit words.
	dataOffWords := int(tcp[12] >> 4)
	if dataOffWords < 5 {
		return nil, 0, 0, nil, false
	}
	tcpHdrTotal := dataOffWords * 4
	if tcpHdrTotal > len(tcp) {
		return nil, 0, 0, nil, false
	}

	// Walk TCP options to find the timestamp (kind=8, len=10). Options
	// occupy tcp[20:tcpHdrTotal]. Kinds 0 (EOL) and 1 (NOP) are single-
	// byte; everything else is kind, len, then (len-2) bytes of value.
	var peerTsVal uint32
	for i := tcpHdrSize; i < tcpHdrTotal; {
		kind := tcp[i]
		if kind == 0 { // End-of-options
			break
		}
		if kind == 1 { // NOP
			i++
			continue
		}
		if i+1 >= tcpHdrTotal {
			break
		}
		olen := int(tcp[i+1])
		if olen < 2 || i+olen > tcpHdrTotal {
			break
		}
		if kind == 8 && olen == 10 {
			peerTsVal = binary.BigEndian.Uint32(tcp[i+2 : i+6])
			break
		}
		i += olen
	}

	payload := tcp[tcpHdrTotal:]
	return srcIP, srcPort, peerTsVal, payload, true
}
