//go:build linux

package socket

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

// TestBPFCompiledFilter_MatchesPcap verifies that the BPF instructions
// we hand to afpacket are bytewise identical to what the pcap filter
// compiler produces for the same string. Catches regressions where
// the pcap → afpacket conversion (pcapBPFToBPFInstructions) drops or
// transposes fields.
func TestBPFCompiledFilter_MatchesPcap(t *testing.T) {
	const port = 443
	filter := "tcp and dst port 443"

	pcapIns, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, afpacketFrameSize, filter)
	if err != nil {
		t.Fatalf("compile filter: %v", err)
	}
	raw := pcapBPFToBPFInstructions(pcapIns)
	if len(raw) != len(pcapIns) {
		t.Fatalf("len(raw)=%d len(pcapIns)=%d", len(raw), len(pcapIns))
	}
	for i := range pcapIns {
		if raw[i].Op != pcapIns[i].Code ||
			raw[i].Jt != pcapIns[i].Jt ||
			raw[i].Jf != pcapIns[i].Jf ||
			raw[i].K != pcapIns[i].K {
			t.Fatalf("ins[%d] mismatch: pcap=%+v raw=%+v", i, pcapIns[i], raw[i])
		}
	}
	_ = port
}

// TestBPFCompiledFilter_VariedPorts exercises the compiler across a
// few ports to make sure the conversion isn't accidentally
// port-dependent.
func TestBPFCompiledFilter_VariedPorts(t *testing.T) {
	for _, p := range []int{80, 443, 8080, 65535} {
		filter := pcapFilterString(p)
		pcapIns, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, afpacketFrameSize, filter)
		if err != nil {
			t.Fatalf("port %d: %v", p, err)
		}
		raw := pcapBPFToBPFInstructions(pcapIns)
		if len(raw) == 0 {
			t.Fatalf("port %d: empty BPF program", p)
		}
		// First instruction should be a load of the ethertype field —
		// stable across libpcap versions for "tcp and dst port N".
		if raw[0].Op == 0 {
			t.Fatalf("port %d: first instruction Op=0 — conversion likely dropped Code", p)
		}
	}
}

func pcapFilterString(port int) string {
	// Match the production string from newPacketReader.
	return "tcp and dst port " + itoa(port)
}

// itoa avoids pulling fmt + strconv just for a base-10 conversion in
// a single test helper. Fast enough at test scale.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// TestUint16PidSalt_Stable verifies the salt is deterministic for the
// process. Important so that ALL fanout readers in the same process
// get the same fanout ID (required by the kernel to actually fan out).
func TestUint16PidSalt_Stable(t *testing.T) {
	a := uint16PidSalt()
	b := uint16PidSalt()
	if a != b {
		t.Fatalf("salt drift: a=%d b=%d", a, b)
	}
}

// fakeTPacket models the gopacket/afpacket TPacket subset our
// afpacketReader actually uses (ZeroCopyReadPacketData → byte slice,
// Close). Lets us unit-test the drain/dispatch loop without binding
// a real raw socket (which requires CAP_NET_RAW + an interface).
type fakeTPacket struct {
	mu      sync.Mutex
	queue   [][]byte
	closed  atomic.Bool
	drained atomic.Int32 // total ZeroCopyReadPacketData calls
}

func (f *fakeTPacket) ZeroCopyReadPacketData() ([]byte, error) {
	f.drained.Add(1)
	for {
		if f.closed.Load() {
			return nil, errClosed{}
		}
		f.mu.Lock()
		if len(f.queue) > 0 {
			p := f.queue[0]
			f.queue = f.queue[1:]
			f.mu.Unlock()
			return p, nil
		}
		f.mu.Unlock()
		// Spin briefly; tests push deterministically and close to wake.
	}
}

func (f *fakeTPacket) push(b []byte) {
	f.mu.Lock()
	f.queue = append(f.queue, b)
	f.mu.Unlock()
}

func (f *fakeTPacket) Close() { f.closed.Store(true) }

type errClosed struct{}

func (errClosed) Error() string { return "closed" }
