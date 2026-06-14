package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket/pcap"
)

type RecvHandle struct {
	handle *pcap.Handle
	// sender is the paired SendHandle, set by PacketConn.New after both
	// handles are constructed. When non-nil, each Read forwards the
	// peer's TCP timestamp into sender.recordPeerTSVal so the next
	// outbound segment can echo it as tsEcr. nil-safe: stays nil in
	// tests that construct RecvHandle standalone.
	sender *SendHandle
}

func NewRecvHandle(cfg *conf.Network) (*RecvHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	return &RecvHandle{handle: handle}, nil
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
// Direct byte parser (recv_handle_parse.go) — replaces the old gopacket
// NewPacket + layer-walk path. ~5-10× faster on this code path and 0
// allocations vs ~7 per call from gopacket's interface dispatch. Stealth-
// neutral (parser-only; doesn't touch the wire).
func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	for {
		data, _, err := h.handle.ReadPacketData()
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
		// srcIP and payload are slices into `data`. gopacket's pcap
		// wrapper allocates a fresh Go-owned buffer per ReadPacketData
		// call (the CGo bridge does a copy), so these slices stay valid
		// for as long as the caller retains them — no separate copy
		// needed. socket.go::ReadFrom immediately copies the payload
		// into the user's buffer; KCP retains the *net.UDPAddr per
		// session so the IP slice is rooted from there.
		return payload, &net.UDPAddr{IP: srcIP, Port: int(srcPort)}, nil
	}
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
