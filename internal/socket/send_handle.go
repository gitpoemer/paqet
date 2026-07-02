package socket

import (
	"container/list"
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
	"paqet/internal/pkg/iterator"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket/pcap"
)

// clientTCPFCap bounds the per-client TCP-flag-iterator LRU. Each entry is
// ~80 bytes (iterator + list element header + map slot) so 256k entries is
// ~20 MB resident.
//
// Raised from 16k → 256k in alpha.33 for 30k+ user scenarios; the previous
// 16k cap meant active clients got evicted every new connection on busy
// servers. 256k accommodates large fleets without thrash. Sharded across
// clientTCPFShards so the per-shard cap is clientTCPFCap/clientTCPFShards.
const clientTCPFCap = 256 * 1024

// peerTSCap bounds the peer-TCP-timestamp LRU. The recv path calls
// recordPeerTSVal on EVERY inbound packet keyed by (srcIP, srcPort),
// including from peers that never complete the paqet-protocol handshake
// (random TCP probes, scanners, traffic the BPF filter lets through but
// that's destined elsewhere). Without an explicit cap those entries leak
// forever — small per-entry but unbounded over a long-running process.
// Same cap as clientTCPF for matching scale assumptions.
const peerTSCap = 256 * 1024

// clientTCPFEntry is the value stored in the LRU map. `iter` is the
// per-client flag iterator; `elem` is the entry's position in the LRU
// list so a hit on getClientTCPF can move-to-front in O(1).
type clientTCPFEntry struct {
	iter *iterator.Iterator[conf.TCPF]
	elem *list.Element // points back to the list node holding the map key
}

// clientTCPFShards is the count of shards that make up the per-client
// TCP-flag-iterator map. Sharding splits the single hot Mutex into N
// shards each with its own lock, so per-packet getClientTCPF lookups
// across distinct peers contend on disjoint shards. 16 shards bounds
// the contention reduction without bloating struct size — at 30k
// users → ~1875 entries per shard, ~12 µs of lock time/sec/shard.
const clientTCPFShards = 16

// clientTCPFPerShardCap = ceil(clientTCPFCap / clientTCPFShards). Per
// shard cap; total system cap is clientTCPFCap.
const clientTCPFPerShardCap = (clientTCPFCap + clientTCPFShards - 1) / clientTCPFShards

// tcpFShard is one bucket of the sharded clientTCPF map. Each shard
// owns its mutex, map, and LRU list — independent of the others.
type tcpFShard struct {
	mu  sync.Mutex
	m   map[uint64]*clientTCPFEntry
	lru *list.List
}

type TCPF struct {
	// tcpF is the GLOBAL iterator returned to peers that don't have a
	// per-client entry yet. Unsharded — accessed via Next() which is
	// internally synchronized in iterator.Iterator.
	tcpF iterator.Iterator[conf.TCPF]
	// shards splits the per-client lookup across clientTCPFShards
	// independent buckets keyed by (hash mod clientTCPFShards).
	shards [clientTCPFShards]tcpFShard
}

// shardFor returns the shard responsible for the given hash key.
func (t *TCPF) shardFor(key uint64) *tcpFShard {
	return &t.shards[key%clientTCPFShards]
}

type SendHandle struct {
	handle *pcap.Handle
	// writeMu serializes pcap injection. libpcap's pcap_sendpacket /
	// WritePacketData is NOT thread-safe, yet one PacketConn (hence one
	// *pcap.Handle) is shared by every server-side KCP session — each with
	// its own tx goroutine calling Write concurrently. Only the injection is
	// guarded; serialization into the pooled scratch buffer stays outside the
	// lock (sync.Pool is already concurrency-safe). Restores the guard the
	// hand-rolled emitter rewrite dropped; matches upstream f0b60be.
	writeMu     sync.Mutex
	srcIPv4     net.IP
	srcIPv4RHWA net.HardwareAddr
	srcIPv6     net.IP
	srcIPv6RHWA net.HardwareAddr
	// cfgInterfaceMAC is the outbound interface's HW address. Snapshotted
	// here so the hand-rolled serializer (send_handle_emit.go) can read it
	// without poking the ethPool.
	cfgInterfaceMAC net.HardwareAddr
	srcPort         uint16
	time            uint32
	tsCounter       uint32
	tcpF            TCPF
	// scratchPool reuses outbound scratch buffers sized for the largest
	// packet we might emit (eth + ipv6 + max-tcp-options + payload).
	// Hand-rolled emitter (send_handle_emit.go) writes into the pooled
	// slice directly; pcap.WritePacketData copies it before returning.
	scratchPool sync.Pool
	// peerTS holds the most recently observed peer TCP-timestamp value
	// per peer (option kind=8), keyed by hash.IPAddr(peerIP, peerPort).
	// nextPacketFields uses it to emit tsEcr that actually echoes the
	// peer, so a DPI tracking timestamp coherence sees real TCP
	// semantics instead of the synthetic tsEcr formula.
	//
	// Changed from sync.Map to a bounded LRU in alpha.33 — sync.Map
	// grew unbounded over time (every inbound packet from any peer
	// inserted, but cleanup only fired on smux session close). Server-
	// side BPF passes ALL inbound TCP to our port, so scanners and
	// random probes accumulated entries forever. peerTSCap caps it.
	peerTS *peerTSStore
}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction out: %v", err)
		}
	}

	sh := &SendHandle{
		handle:  handle,
		srcPort: uint16(cfg.Port),
		tcpF: TCPF{
			tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF},
		},
		peerTS: newPeerTSStore(peerTSCap),
		time:   uint32(time.Now().UnixNano() / int64(time.Millisecond)),
	}
	for i := range sh.tcpF.shards {
		sh.tcpF.shards[i].m = make(map[uint64]*clientTCPFEntry, clientTCPFPerShardCap/8)
		sh.tcpF.shards[i].lru = list.New()
	}
	sh.cfgInterfaceMAC = cfg.Interface.HardwareAddr
	if cfg.IPv4.Addr != nil {
		sh.srcIPv4 = cfg.IPv4.Addr.IP
		sh.srcIPv4RHWA = cfg.IPv4.Router
	}
	if cfg.IPv6.Addr != nil {
		sh.srcIPv6 = cfg.IPv6.Addr.IP
		sh.srcIPv6RHWA = cfg.IPv6.Router
	}
	return sh, nil
}

// Write serializes a single TCP-mimic packet carrying the given payload to
// the given destination, then injects it via pcap.
//
// Implementation note: this used to call gopacket.SerializeLayers with
// FixLengths+ComputeChecksums, plus a chain of header-pool Gets. Profiling
// (see BenchmarkSerialize_*) showed gopacket spending ~4.8μs per 1400-byte
// packet against 0.8μs for a hand-rolled byte emitter — 6× faster, 0
// allocs vs 13. The hand-rolled path is byte-identical to gopacket's
// output across every flag combo + payload size in
// TestSerializeEquivalence, so the wire format is unchanged.
func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr) error {
	pf := h.nextPacketFields(addr.IP, uint16(addr.Port))

	scratchAny := h.scratchPool.Get()
	var scratch []byte
	need := maxPacketSize(len(payload))
	if scratchAny == nil {
		scratch = make([]byte, need)
	} else {
		scratch = scratchAny.([]byte)
		if cap(scratch) < need {
			scratch = make([]byte, need)
		} else {
			scratch = scratch[:need]
		}
	}
	n := h.serializePacketTo(scratch, payload, pf)
	h.writeMu.Lock()
	err := h.handle.WritePacketData(scratch[:n])
	h.writeMu.Unlock()
	// Reset to full cap before returning to the pool so the next Get sees
	// the full backing array; serializePacketTo writes from offset 0 so
	// stale bytes from a previous call are harmless.
	h.scratchPool.Put(scratch[:cap(scratch)])
	return err
}

// nextPacketFields mints the volatile fields for one outbound packet from
// the per-handle counter. Factored out so the serializer is a pure function.
func (h *SendHandle) nextPacketFields(dstIP net.IP, dstPort uint16) packetFields {
	f := h.getClientTCPF(dstIP, dstPort)
	counter := atomic.AddUint32(&h.tsCounter, 1)
	tsVal := h.time + (counter >> 3)

	pf := packetFields{
		dstIP:   dstIP,
		dstPort: dstPort,
		flags:   f,
		tsVal:   tsVal,
		// Mint a varying 16-bit IP Identification from the counter via
		// Knuth's multiplicative hash. Cheap (one mul + one shift), no
		// extra atomic. Looks uniform to a wire observer — no clean
		// "Identification=0 in 100% of frames" fingerprint.
		ipID: uint16((counter * 0x9E3779B9) >> 16),
	}
	if f.SYN {
		pf.seq = 1 + (counter & 0x7)
		if f.ACK {
			pf.ack = pf.seq + 1
		}
		pf.tsEcr = 0
	} else {
		// Echo the most recently observed peer timestamp if recv has
		// seen one for this flow. Falls back to a synthetic value when
		// we haven't yet received any timestamped segment from this
		// peer (first reply during handshake, or a peer that doesn't
		// negotiate timestamps). The fallback still varies per packet
		// so it doesn't itself fingerprint as "tsEcr=0 always".
		if v := h.loadPeerTSVal(dstIP, dstPort); v != 0 {
			pf.tsEcr = v
		} else {
			pf.tsEcr = tsVal - (counter%200 + 50)
		}
		seq := h.time + (counter << 7)
		pf.seq = seq
		pf.ack = seq - (counter & 0x3FF) + 1400
	}
	return pf
}

// loadPeerTSVal returns the most recently observed peer TCP-timestamp
// value for the given flow, or 0 if unseen.
func (h *SendHandle) loadPeerTSVal(peerIP net.IP, peerPort uint16) uint32 {
	return h.peerTS.load(hash.IPAddr(peerIP, peerPort))
}

// recordPeerTSVal stores the most recently observed peer TCP-timestamp
// value for the given flow. recv_handle.Read calls it after
// parseInbound. The store enforces a bounded LRU; tsVal==0 is treated
// as "no timestamp this packet" and skipped.
func (h *SendHandle) recordPeerTSVal(peerIP net.IP, peerPort uint16, tsVal uint32) {
	h.peerTS.store(hash.IPAddr(peerIP, peerPort), tsVal)
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	key := hash.IPAddr(dstIP, dstPort)
	sh := h.tcpF.shardFor(key)
	sh.mu.Lock()
	if e, ok := sh.m[key]; ok {
		// Move-to-front: this client is the most recently used.
		sh.lru.MoveToFront(e.elem)
		f := e.iter.Next()
		sh.mu.Unlock()
		return f
	}
	sh.mu.Unlock()
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a := *addr.(*net.UDPAddr)
	key := hash.IPAddr(a.IP, uint16(a.Port))

	sh := h.tcpF.shardFor(key)
	sh.mu.Lock()
	defer sh.mu.Unlock()

	if e, ok := sh.m[key]; ok {
		// Same key, fresh iterator. Move to front.
		e.iter = &iterator.Iterator[conf.TCPF]{Items: f}
		sh.lru.MoveToFront(e.elem)
		return
	}

	// New key. If we'd exceed the per-shard cap, evict the LRU tail.
	// The legitimate client being evicted has presumably gone idle (no
	// outbound traffic means no move-to-front in getClientTCPF) — losing
	// the protocol-negotiated flag pattern isn't a correctness break
	// since getClientTCPF falls back to the global LF iterator on a miss.
	if sh.lru.Len() >= clientTCPFPerShardCap {
		if tail := sh.lru.Back(); tail != nil {
			evictedKey := tail.Value.(uint64)
			delete(sh.m, evictedKey)
			sh.lru.Remove(tail)
			h.peerTS.delete(evictedKey)
		}
	}

	elem := sh.lru.PushFront(key)
	sh.m[key] = &clientTCPFEntry{
		iter: &iterator.Iterator[conf.TCPF]{Items: f},
		elem: elem,
	}
}

// dropClientTCPF removes the per-remote iterator. The server calls this when
// a smux session terminates so we don't accumulate dead entries for ever.
func (h *SendHandle) dropClientTCPF(addr net.Addr) {
	a, ok := addr.(*net.UDPAddr)
	if !ok || a == nil {
		return
	}
	key := hash.IPAddr(a.IP, uint16(a.Port))
	sh := h.tcpF.shardFor(key)
	sh.mu.Lock()
	if e, ok := sh.m[key]; ok {
		sh.lru.Remove(e.elem)
		delete(sh.m, key)
	}
	sh.mu.Unlock()
	h.peerTS.delete(key)
}

func (h *SendHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
