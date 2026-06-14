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
// ~80 bytes (iterator + list element header + map slot) so 16k entries is
// ~1.3 MB resident.
//
// 16k is well above the realistic count of concurrent active clients on a
// single paqet server, but high enough that an attacker minting fresh-port
// connections needs ~16k inserts before evicting a single legitimate
// client — and legitimate clients with ongoing outbound traffic stay at
// the LRU front via getClientTCPF, so the typical attacker eviction
// targets are dormant entries, not active ones.
const clientTCPFCap = 16384

// clientTCPFEntry is the value stored in the LRU map. `iter` is the
// per-client flag iterator; `elem` is the entry's position in the LRU
// list so a hit on getClientTCPF can move-to-front in O(1).
type clientTCPFEntry struct {
	iter *iterator.Iterator[conf.TCPF]
	elem *list.Element // points back to the list node holding the map key
}

type TCPF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*clientTCPFEntry
	// LRU ordering: front = most recently used, back = oldest.
	// container/list element values are the uint64 map keys.
	lru *list.List
	// Single Mutex: both getClientTCPF (move-to-front) and
	// setClientTCPF (insert/evict) mutate the list, so RWMutex would
	// degrade to Lock on every call anyway.
	mu sync.Mutex
}

type SendHandle struct {
	handle      *pcap.Handle
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
			tcpF:       iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF},
			clientTCPF: make(map[uint64]*clientTCPFEntry, clientTCPFCap),
			lru:        list.New(),
		},
		time: uint32(time.Now().UnixNano() / int64(time.Millisecond)),
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
	err := h.handle.WritePacketData(scratch[:n])
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
	}
	if f.SYN {
		pf.seq = 1 + (counter & 0x7)
		if f.ACK {
			pf.ack = pf.seq + 1
		}
		pf.tsEcr = 0
	} else {
		pf.tsEcr = tsVal - (counter%200 + 50)
		seq := h.time + (counter << 7)
		pf.seq = seq
		pf.ack = seq - (counter & 0x3FF) + 1400
	}
	return pf
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	key := hash.IPAddr(dstIP, dstPort)
	h.tcpF.mu.Lock()
	if e, ok := h.tcpF.clientTCPF[key]; ok {
		// Move-to-front: this client is the most recently used.
		h.tcpF.lru.MoveToFront(e.elem)
		f := e.iter.Next()
		h.tcpF.mu.Unlock()
		return f
	}
	h.tcpF.mu.Unlock()
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a := *addr.(*net.UDPAddr)
	key := hash.IPAddr(a.IP, uint16(a.Port))

	h.tcpF.mu.Lock()
	defer h.tcpF.mu.Unlock()

	if e, ok := h.tcpF.clientTCPF[key]; ok {
		// Same key, fresh iterator. Move to front.
		e.iter = &iterator.Iterator[conf.TCPF]{Items: f}
		h.tcpF.lru.MoveToFront(e.elem)
		return
	}

	// New key. If we'd exceed the cap, evict the LRU tail. The legitimate
	// client whose entry is being moved to the LRU tail by attacker-driven
	// inserts has presumably gone idle (no outbound traffic means no
	// move-to-front in getClientTCPF) — evicting them costs the protocol-
	// negotiated flag pattern but isn't a correctness break, since
	// getClientTCPF falls back to the default LF iterator on a miss.
	if h.tcpF.lru.Len() >= clientTCPFCap {
		if tail := h.tcpF.lru.Back(); tail != nil {
			evictedKey := tail.Value.(uint64)
			delete(h.tcpF.clientTCPF, evictedKey)
			h.tcpF.lru.Remove(tail)
		}
	}

	elem := h.tcpF.lru.PushFront(key)
	h.tcpF.clientTCPF[key] = &clientTCPFEntry{
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
	h.tcpF.mu.Lock()
	if e, ok := h.tcpF.clientTCPF[key]; ok {
		h.tcpF.lru.Remove(e.elem)
		delete(h.tcpF.clientTCPF, key)
	}
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
