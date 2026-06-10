package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type RecvHandle struct {
	handle *pcap.Handle
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

// Read returns the next TCP-payload-bearing packet observed on the wire,
// along with the source UDP-formatted address. Loops past benign captures
// (handshake-only segments, ARP that slipped past BPF, malformed frames)
// so the upper PacketConn layer never sees a `(0, nil-addr, nil-err)` short
// read — which KCP would otherwise interpret as session shutdown. See
// OPTIMIZE_NOTES.md C3.
func (h *RecvHandle) Read() ([]byte, net.Addr, error) {
	for {
		data, _, err := h.handle.ReadPacketData()
		if err != nil {
			return nil, nil, err
		}
		p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

		netLayer := p.NetworkLayer()
		if netLayer == nil {
			continue
		}

		addr := &net.UDPAddr{}
		switch netLayer.LayerType() {
		case layers.LayerTypeIPv4:
			addr.IP = netLayer.(*layers.IPv4).SrcIP
		case layers.LayerTypeIPv6:
			addr.IP = netLayer.(*layers.IPv6).SrcIP
		default:
			continue
		}

		trLayer := p.TransportLayer()
		if trLayer == nil {
			continue
		}
		switch trLayer.LayerType() {
		case layers.LayerTypeTCP:
			addr.Port = int(trLayer.(*layers.TCP).SrcPort)
		case layers.LayerTypeUDP:
			addr.Port = int(trLayer.(*layers.UDP).SrcPort)
		default:
			continue
		}

		appLayer := p.ApplicationLayer()
		if appLayer == nil {
			continue
		}
		payload := appLayer.Payload()
		if len(payload) == 0 {
			continue
		}
		return payload, addr, nil
	}
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
