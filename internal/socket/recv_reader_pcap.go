//go:build !linux

package socket

import (
	"fmt"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket/pcap"
)

// pcapPacketReader is the libpcap-backed recv path. Used on every OS
// except Linux. On Linux we prefer afpacket TPACKET_V3 (see
// recv_reader_afpacket_linux.go) for multi-CPU mmap'd receive.
type pcapPacketReader struct {
	h *pcap.Handle
}

func newPacketReader(cfg *conf.Network) (packetReader, error) {
	h, err := newHandle(cfg)
	if err != nil {
		return nil, err
	}
	// SetDirection is not fully supported on Windows Npcap.
	if runtime.GOOS != "windows" {
		if err := h.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("set pcap direction in: %v", err)
		}
	}
	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if err := h.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("set BPF filter: %w", err)
	}
	return &pcapPacketReader{h: h}, nil
}

func (r *pcapPacketReader) ReadPacketData() ([]byte, error) {
	data, _, err := r.h.ReadPacketData()
	return data, err
}

func (r *pcapPacketReader) Close() {
	if r.h != nil {
		r.h.Close()
	}
}
