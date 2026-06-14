package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
)

type RecvHandle struct {
	reader packetReader
	// sender is the paired SendHandle, set by PacketConn.New after both
	// handles are constructed. When non-nil, each Read forwards the
	// peer's TCP timestamp into sender.recordPeerTSVal so the next
	// outbound segment can echo it as tsEcr. nil-safe: stays nil in
	// tests that construct RecvHandle standalone.
	sender *SendHandle
}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	r, err := newPacketReader(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open recv reader: %w", err)
	}
	return &RecvHandle{reader: r}, nil
}

// AttachSender wires this RecvHandle to its paired SendHandle so the
// recv path can feed observed peer TCP timestamps into the sender's
// per-peer tsEcr cache.
func (h *RecvHandle) AttachSender(sh *SendHandle) {
	h.sender = sh
}

// Read returns the next TCP-payload-bearing packet observed on the wire,
// along with the source UDP-formatted address. Loops past benign captures
// (handshake-only segments, ARP that slipped past BPF, malformed frames)
// so the upper PacketConn layer never sees a `(0, nil-addr, nil-err)` short
// read — which KCP would otherwise interpret as session shutdown.
//
// The recv mechanism (libpcap on non-Linux, afpacket TPACKET_V3 on Linux)
// is hidden behind packetReader. Stealth is unchanged: this is parse-side
// only; the wire interpretation in parseInbound is the same regardless
// of which kernel captured the frame.
func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	for {
		data, err := h.reader.ReadPacketData()
		if err != nil {
			return nil, nil, err
		}
		srcIP, srcPort, peerTsVal, payload, ok := parseInbound(data)
		if !ok {
			continue
		}
		// Track peer's TCP timestamp BEFORE the payload-length filter:
		// pure-ACK segments from the peer carry the freshest tsVal but
		// have no application payload. Skipping them would mean tsEcr
		// drifts hundreds of ms behind real semantics.
		if h.sender != nil {
			h.sender.recordPeerTSVal(srcIP, srcPort, peerTsVal)
		}
		if len(payload) == 0 {
			continue
		}
		// srcIP and payload are slices into `data`. Both backends
		// (pcap CGo copy + afpacket per-frame Go-side copy in drain())
		// give us Go-owned bytes that stay valid until the caller
		// drops the reference. socket.go::ReadFrom immediately copies
		// the payload into the user's buffer; KCP retains the
		// *net.UDPAddr per session so the IP slice is rooted from
		// there.
		return payload, &net.UDPAddr{IP: srcIP, Port: int(srcPort)}, nil
	}
}

func (h *RecvHandle) Close() {
	if h.reader != nil {
		h.reader.Close()
	}
}
