package socket

// Hand-rolled inbound packet parser. Mirror image of send_handle_emit.go.
//
// Replaces gopacket.NewPacket(data, LayerTypeEthernet, NoCopy) and the
// layer.NetworkLayer() / .TransportLayer() / .ApplicationLayer() walks
// with a direct byte parse. Avoids gopacket's allocation of a *Packet
// struct plus per-layer interface dispatch per inbound packet.
//
// Returns:
//   - srcIP   — slice into `data` (do NOT retain past the next ReadPacketData)
//   - srcPort — TCP source port
//   - payload — slice into `data` (same retention constraint)
//   - ok      — false on any malformed/short/unsupported frame; caller
//               should continue to the next packet, NOT surface as an error.
//
// Stealth: parser-only. No wire bytes change.

import (
	"encoding/binary"
)

// parseInbound decodes one ethernet/IP/TCP frame. Caller must ensure the
// caller holds `data` stable until they're done with the returned slices.
func parseInbound(data []byte) (srcIP []byte, srcPort uint16, payload []byte, ok bool) {
	if len(data) < ethHdrSize+ipv4HdrSize+tcpHdrSize {
		return nil, 0, nil, false
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
		return nil, 0, nil, false
	}
}

func parseInboundIPv4(data []byte) (srcIP []byte, srcPort uint16, payload []byte, ok bool) {
	ip := data[ethHdrSize:]
	if len(ip) < ipv4HdrSize {
		return nil, 0, nil, false
	}

	// Version (high nibble of byte 0) must be 4. IHL (low nibble) is the
	// number of 32-bit words in the IP header; 5 = no options (20 bytes).
	verIhl := ip[0]
	if verIhl>>4 != 4 {
		return nil, 0, nil, false
	}
	ihlWords := int(verIhl & 0x0F)
	if ihlWords < 5 {
		return nil, 0, nil, false
	}
	ipHdrLen := ihlWords * 4
	if len(ip) < ipHdrLen {
		return nil, 0, nil, false
	}

	// Protocol must be TCP.
	if ip[9] != ipProtoTCP {
		return nil, 0, nil, false
	}

	// Total length includes IP header + TCP header + payload.
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ipHdrLen {
		return nil, 0, nil, false
	}
	// Some drivers add trailing padding to bring the frame to the minimum
	// 64-byte Ethernet size; truncate to the IP-declared length.
	if totalLen > len(ip) {
		// IP declares more bytes than we received — runt frame.
		return nil, 0, nil, false
	}

	srcIP = ip[12:16]
	tcp := ip[ipHdrLen:totalLen]
	return finishTCPParse(tcp, srcIP)
}

func parseInboundIPv6(data []byte) (srcIP []byte, srcPort uint16, payload []byte, ok bool) {
	if len(data) < ethHdrSize+ipv6HdrSize+tcpHdrSize {
		return nil, 0, nil, false
	}
	ip := data[ethHdrSize:]
	// Version is the high nibble of byte 0.
	if ip[0]>>4 != 6 {
		return nil, 0, nil, false
	}

	// NextHeader at byte 6. For TCP without extension headers it's 6.
	// We don't traverse extension-header chains — paqet's own traffic
	// doesn't use them, and a peer sending them just gets dropped here.
	if ip[6] != ipProtoTCP {
		return nil, 0, nil, false
	}

	payloadLen := int(binary.BigEndian.Uint16(ip[4:6]))
	if payloadLen < tcpHdrSize {
		return nil, 0, nil, false
	}
	if ipv6HdrSize+payloadLen > len(ip) {
		return nil, 0, nil, false
	}

	srcIP = ip[8:24]
	tcp := ip[ipv6HdrSize : ipv6HdrSize+payloadLen]
	return finishTCPParse(tcp, srcIP)
}

// finishTCPParse extracts (srcPort, payload) from a TCP segment whose
// bounds have already been validated as in-range of the underlying buffer.
func finishTCPParse(tcp, srcIP []byte) ([]byte, uint16, []byte, bool) {
	if len(tcp) < tcpHdrSize {
		return nil, 0, nil, false
	}
	srcPort := binary.BigEndian.Uint16(tcp[0:2])

	// Data offset: high nibble of byte 12, in 32-bit words.
	dataOffWords := int(tcp[12] >> 4)
	if dataOffWords < 5 {
		return nil, 0, nil, false
	}
	tcpHdrTotal := dataOffWords * 4
	if tcpHdrTotal > len(tcp) {
		return nil, 0, nil, false
	}
	payload := tcp[tcpHdrTotal:]
	return srcIP, srcPort, payload, true
}
