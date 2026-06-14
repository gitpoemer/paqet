//go:build linux

package socket

import (
	"fmt"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"runtime"
	"time"

	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/net/bpf"
)

// afpacketReader is the high-throughput recv path on Linux. Uses
// gopacket/afpacket which wraps AF_PACKET TPACKET_V3:
//
//   - mmap'd ring buffer for zero-copy frame delivery (no per-frame
//     kernel-to-user copy like pcap's read() loop)
//   - PACKET_FANOUT_CPU spreads frames across multiple reader sockets
//     by CPU, letting paqet exploit more than one core on the recv
//     hot path
//
// One reader per CPU pulls from its slice of the ring; a single
// goroutine drains all readers and feeds them to the parser via
// the packets channel. Caller sees a normal sequential stream of
// frames via ReadPacketData.
//
// Stealth: parse path is byte-for-byte identical to the pcap-backed
// reader. The wire interpretation (parseInbound) doesn't care which
// kernel mechanism captured the frame.
type afpacketReader struct {
	readers []*afpacket.TPacket
	packets chan []byte
	errs    chan error
	stop    chan struct{}
}

// afpacketBlockSize / NumBlocks: TPACKET_V3 requires (frameSize *
// framesPerBlock = blockSize). 1MB blocks × 32 blocks = 32MB ring per
// reader. With NumCPU readers (e.g. 4) that's 128MB total — sized to
// match the 32MB sysctl rmem_max we recommend in DEPLOYMENT.md.
const (
	afpacketFrameSize = 65536
	afpacketBlockSize = 1 << 20 // 1 MB
	afpacketNumBlocks = 32
	afpacketTimeout   = 500 * time.Millisecond
)

func newPacketReader(cfg *conf.Network) (packetReader, error) {
	ifaceName := cfg.Interface.Name
	if runtime.GOOS == "windows" {
		// belt-and-suspenders: this file is linux-only via build tag,
		// but keep parity with the pcap path for future portability.
		ifaceName = cfg.GUID
	}

	// Use one reader per CPU. Each gets its own AF_PACKET socket and
	// joins the same fanout group; the kernel hashes by CPU so we
	// avoid lock contention on a shared ring.
	numReaders := runtime.NumCPU()
	if numReaders < 1 {
		numReaders = 1
	}
	if numReaders > 16 {
		// Diminishing returns past 16 fanout slots, more memory cost.
		numReaders = 16
	}

	// Compile the BPF filter via pcap once. afpacket needs raw bpf
	// instructions; we reuse pcap's compiler so the filter string
	// matches the existing semantics ("tcp and dst port N").
	filterStr := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	pcapIns, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, afpacketFrameSize, filterStr)
	if err != nil {
		return nil, fmt.Errorf("compile BPF filter %q: %w", filterStr, err)
	}
	rawIns := pcapBPFToBPFInstructions(pcapIns)

	r := &afpacketReader{
		readers: make([]*afpacket.TPacket, 0, numReaders),
		packets: make(chan []byte, 1024),
		errs:    make(chan error, 1),
		stop:    make(chan struct{}),
	}

	// Same fanout ID for all readers in this listener. Unique per
	// paqet process via PID + port hash so two paqet instances on
	// the same host don't collide.
	fanoutID := (uint16(cfg.Port) ^ uint16PidSalt()) | 1 // ensure nonzero

	for i := 0; i < numReaders; i++ {
		tp, err := afpacket.NewTPacket(
			afpacket.OptInterface(ifaceName),
			afpacket.OptFrameSize(afpacketFrameSize),
			afpacket.OptBlockSize(afpacketBlockSize),
			afpacket.OptNumBlocks(afpacketNumBlocks),
			afpacket.OptPollTimeout(afpacketTimeout),
			afpacket.SocketRaw,
			afpacket.TPacketVersion3,
		)
		if err != nil {
			r.closeReaders()
			return nil, fmt.Errorf("create TPacket %d/%d: %w", i, numReaders, err)
		}
		if err := tp.SetBPF(rawIns); err != nil {
			tp.Close()
			r.closeReaders()
			return nil, fmt.Errorf("apply BPF to TPacket %d: %w", i, err)
		}
		if err := tp.SetFanout(afpacket.FanoutCPU, fanoutID); err != nil {
			// Fanout failure isn't fatal — single-reader mode still
			// works, just without the multi-CPU win. Log and continue.
			flog.Errorf("afpacket fanout setup failed on reader %d (single-reader fallback): %v", i, err)
		}
		r.readers = append(r.readers, tp)
		go r.drain(tp)
	}

	flog.Infof("recv path: afpacket TPACKET_V3 (%d fanout readers, %d MB ring each)",
		numReaders, afpacketBlockSize*afpacketNumBlocks/(1<<20))
	return r, nil
}

// drain runs in its own goroutine per fanout reader. Pulls frames
// off the ring and pushes them onto the shared packets channel for
// the single-consumer ReadPacketData caller. Allocates a fresh
// per-frame copy because the underlying ring memory is reused by
// the kernel as soon as we release the slot.
func (r *afpacketReader) drain(tp *afpacket.TPacket) {
	for {
		select {
		case <-r.stop:
			return
		default:
		}
		data, _, err := tp.ZeroCopyReadPacketData()
		if err != nil {
			select {
			case r.errs <- err:
			default:
			}
			return
		}
		// Zero-copy data is only valid until the next read on THIS
		// reader. Copy to give the consumer stable bytes; the
		// allocation cost is amortized by avoiding the kernel-side
		// copy that pcap's read path does.
		buf := make([]byte, len(data))
		copy(buf, data)
		select {
		case r.packets <- buf:
		case <-r.stop:
			return
		}
	}
}

func (r *afpacketReader) ReadPacketData() ([]byte, error) {
	select {
	case pkt := <-r.packets:
		return pkt, nil
	case err := <-r.errs:
		return nil, err
	case <-r.stop:
		return nil, fmt.Errorf("afpacket reader closed")
	}
}

func (r *afpacketReader) Close() {
	select {
	case <-r.stop:
	default:
		close(r.stop)
	}
	r.closeReaders()
}

func (r *afpacketReader) closeReaders() {
	for _, tp := range r.readers {
		tp.Close()
	}
	r.readers = nil
}

// pcapBPFToBPFInstructions adapts pcap.BPFInstruction (from libpcap)
// into the golang.org/x/net/bpf.RawInstruction type that afpacket
// expects. Field-for-field copy.
func pcapBPFToBPFInstructions(pcapIns []pcap.BPFInstruction) []bpf.RawInstruction {
	out := make([]bpf.RawInstruction, len(pcapIns))
	for i, p := range pcapIns {
		out[i] = bpf.RawInstruction{
			Op: p.Code,
			Jt: p.Jt,
			Jf: p.Jf,
			K:  p.K,
		}
	}
	return out
}

// uint16PidSalt returns a uint16 derived from the current PID so two
// paqet processes on the same host (e.g. server + client both
// running locally) get distinct fanout groups.
func uint16PidSalt() uint16 {
	pid := getpid()
	return uint16((pid >> 16) ^ pid)
}
