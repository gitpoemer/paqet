package socket

import (
	"container/list"
	"net"
	"paqet/internal/conf"
	"paqet/internal/pkg/iterator"
	"sync/atomic"
	"testing"
)

// buildPrimedHandle returns a *SendHandle whose LRU is pre-loaded with `n`
// entries. We skip pcap.NewHandle by leaving h.handle nil — the hot paths
// under benchmark (getClientTCPF / setClientTCPF) only touch h.tcpF.
func buildPrimedHandle(n int) *SendHandle {
	sh := &SendHandle{
		tcpF: TCPF{
			tcpF: iterator.Iterator[conf.TCPF]{Items: []conf.TCPF{{ACK: true, PSH: true}}},
		},
		peerTS: newPeerTSStore(peerTSCap),
	}
	for i := range sh.tcpF.shards {
		sh.tcpF.shards[i].m = make(map[uint64]*clientTCPFEntry)
		sh.tcpF.shards[i].lru = list.New()
	}
	flags := []conf.TCPF{{ACK: true, PSH: true}}
	for _, k := range primeKeys(n) {
		sh.setClientTCPF(addrFromKey(k), flags)
	}
	return sh
}

func primeKeys(n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		// Stir the bits so consecutive i values don't all bucket together
		// in the map; the goal here is unique 64-bit keys, not collision-
		// resistance.
		out[i] = (uint64(i+1) * 2654435761) | (uint64(i+1) << 33)
	}
	return out
}

func addrFromKey(k uint64) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   net.IPv4(byte(k), byte(k>>8), byte(k>>16), byte(k>>24)),
		Port: int(uint16(k >> 32)),
	}
}

// BenchmarkClientTCPF_Read drives only getClientTCPF on a half-full LRU.
// Every call hits move-to-front.
func BenchmarkClientTCPF_Read(b *testing.B) {
	h := buildPrimedHandle(clientTCPFCap / 2)
	keys := primeKeys(clientTCPFCap / 2)
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var i atomic.Uint64
		for pb.Next() {
			a := addrFromKey(keys[int(i.Add(1))%len(keys)])
			h.getClientTCPF(a.IP, uint16(a.Port))
		}
	})
}

// BenchmarkClientTCPF_Mixed_99R_1W is the realistic workload: most
// outbound packets hit getClientTCPF, occasional new clients call
// setClientTCPF. Writes rotate keys past the cap to exercise eviction.
func BenchmarkClientTCPF_Mixed_99R_1W(b *testing.B) {
	h := buildPrimedHandle(clientTCPFCap / 2)
	readKeys := primeKeys(clientTCPFCap / 2)
	flags := []conf.TCPF{{ACK: true, PSH: true}}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		var i atomic.Uint64
		for pb.Next() {
			idx := int(i.Add(1))
			if idx%100 == 0 {
				// Synthesize an always-new key by xoring idx in
				h.setClientTCPF(addrFromKey(uint64(idx)*2654435761|uint64(idx)<<33), flags)
			} else {
				a := addrFromKey(readKeys[idx%len(readKeys)])
				h.getClientTCPF(a.IP, uint16(a.Port))
			}
		}
	})
}
