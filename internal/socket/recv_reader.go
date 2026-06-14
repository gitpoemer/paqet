package socket

// packetReader is the minimal contract the recv path needs from the
// underlying packet capture mechanism. Two implementations:
//
//   - pcapPacketReader (recv_reader_pcap.go) — used on Windows and
//     anywhere afpacket isn't available. Wraps a *pcap.Handle.
//   - afpacketPacketReader (recv_reader_afpacket_linux.go) — Linux
//     only. Wraps gopacket/afpacket's TPacket with TPACKET_V3 mmap
//     ring buffer + PACKET_FANOUT_CPU for multi-CPU receive.
//
// Both produce []byte payloads with the same semantics: each call
// returns the next frame whose BPF filter matched. Slice retention
// rules differ between backends; recv_handle.go's caller copies into
// the consumer's buffer immediately, so retention beyond the next
// call isn't relied on.
//
// Stealth note: this is the RECV path only. No outbound bytes change.
// The wire format paqet emits is determined by SendHandle (alpha.23
// hand-rolled emitter), which is untouched by this change.
type packetReader interface {
	// ReadPacketData returns the next BPF-matched packet's raw bytes.
	// Returns an error if the underlying capture is closed.
	ReadPacketData() ([]byte, error)
	// Close releases the underlying capture handle.
	Close()
}
