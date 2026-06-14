package socket

import (
	"container/list"
	"net"
	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
	"paqet/internal/pkg/iterator"
	"testing"
)

func addrKeyImpl(a *net.UDPAddr) uint64 {
	return hash.IPAddr(a.IP, uint16(a.Port))
}

func newTestHandle() *SendHandle {
	h := &SendHandle{
		tcpF: TCPF{
			tcpF: iterator.Iterator[conf.TCPF]{Items: []conf.TCPF{{ACK: true, PSH: true}}},
		},
		peerTS: newPeerTSStore(peerTSCap),
	}
	for i := range h.tcpF.shards {
		h.tcpF.shards[i].m = make(map[uint64]*clientTCPFEntry)
		h.tcpF.shards[i].lru = list.New()
	}
	return h
}

// totalEntries sums the entry count across all shards. Used by tests
// that don't care which shard a key landed in.
func (h *SendHandle) totalEntries() int {
	n := 0
	for i := range h.tcpF.shards {
		h.tcpF.shards[i].mu.Lock()
		n += h.tcpF.shards[i].lru.Len()
		h.tcpF.shards[i].mu.Unlock()
	}
	return n
}

func mkAddr(a, b, c, d byte, port int) *net.UDPAddr {
	return &net.UDPAddr{IP: net.IPv4(a, b, c, d), Port: port}
}

// TestLRU_EvictsTail confirms that within a single shard, the LRU
// evicts the LEAST recently used entry. Picks three addresses that
// all hash to the SAME shard so LRU semantics are observable as a
// single list (sharding splits the global LRU into N independent
// per-shard LRUs, each preserving the same property).
func TestLRU_EvictsTail(t *testing.T) {
	h := newTestHandle()

	// Find three addresses that land in the same shard. Scan a small
	// address range until we get three colliding hashes.
	var addrs []*net.UDPAddr
	var targetShard uint64
	for octet := byte(0); octet < 200 && len(addrs) < 3; octet++ {
		a := mkAddr(10, 0, 0, octet, 100)
		shardIdx := addrKeyImpl(a) % clientTCPFShards
		if len(addrs) == 0 {
			targetShard = shardIdx
			addrs = append(addrs, a)
			continue
		}
		if shardIdx == targetShard {
			addrs = append(addrs, a)
		}
	}
	if len(addrs) != 3 {
		t.Fatalf("could not find 3 colliding-shard addresses in [10.0.0.0/24]; got %d", len(addrs))
	}
	a1, a2, a3 := addrs[0], addrs[1], addrs[2]

	flags := []conf.TCPF{{ACK: true}}
	h.setClientTCPF(a1, flags) // [1]
	h.setClientTCPF(a2, flags) // [2, 1]
	h.setClientTCPF(a3, flags) // [3, 2, 1]

	// "Touch" 1 via outbound emission — moves it to front.
	h.getClientTCPF(a1.IP, uint16(a1.Port))
	// Order in shard: [1, 3, 2].

	shard := h.tcpF.shardFor(addrKey(a1))
	shard.mu.Lock()
	defer shard.mu.Unlock()
	if shard.lru.Front().Value.(uint64) != addrKey(a1) {
		t.Fatalf("front = %x, want a1 key %x", shard.lru.Front().Value, addrKey(a1))
	}
	tailKey := shard.lru.Back().Value.(uint64)
	if tailKey != addrKey(a2) {
		t.Fatalf("tail = %x, want a2 key %x (LRU order broken)", tailKey, addrKey(a2))
	}
}

// TestLRU_DropRemovesBoth confirms dropClientTCPF cleans both the map
// AND the LRU list (matching memory leak fix). Works regardless of
// which shard the key lands in via totalEntries().
func TestLRU_DropRemovesBoth(t *testing.T) {
	h := newTestHandle()
	a := mkAddr(10, 0, 0, 1, 100)
	h.setClientTCPF(a, []conf.TCPF{{ACK: true}})

	if h.totalEntries() != 1 {
		t.Fatalf("post-insert: total=%d, want 1", h.totalEntries())
	}

	h.dropClientTCPF(a)
	if h.totalEntries() != 0 {
		t.Fatalf("post-drop: total=%d, want 0 (list leak)", h.totalEntries())
	}
}

// TestLRU_SameKeyUpdatesIterator confirms that setClientTCPF for an
// existing key replaces the iterator without leaking the old entry's
// list element. Single-key test — sharding irrelevant.
func TestLRU_SameKeyUpdatesIterator(t *testing.T) {
	h := newTestHandle()
	a := mkAddr(10, 0, 0, 1, 100)

	flagsA := []conf.TCPF{{ACK: true}}
	flagsB := []conf.TCPF{{SYN: true}}

	h.setClientTCPF(a, flagsA)
	if h.totalEntries() != 1 {
		t.Fatalf("post-first-insert: total=%d, want 1", h.totalEntries())
	}

	// Re-insert with different flags. Should NOT add a new entry.
	h.setClientTCPF(a, flagsB)
	if h.totalEntries() != 1 {
		t.Fatalf("post-update: total=%d, want 1 (entry duplicated)", h.totalEntries())
	}

	// Returned flag should reflect flagsB (SYN), not flagsA (ACK).
	got := h.getClientTCPF(a.IP, uint16(a.Port))
	if !got.SYN || got.ACK {
		t.Fatalf("got flags %+v, want SYN-only from flagsB", got)
	}
}

// addrKey duplicates hash.IPAddr's calling convention so tests can
// predict map keys without importing the package's hash function in
// every line.
func addrKey(a *net.UDPAddr) uint64 {
	// Match send_handle.go: hash.IPAddr(a.IP, uint16(a.Port)).
	// We import hash package directly via the production call site;
	// this helper exists so the test reads cleanly.
	return addrKeyImpl(a)
}
