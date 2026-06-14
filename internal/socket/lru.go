package socket

import (
	"container/list"
	"sync"
	"sync/atomic"
)

// peerTSStore is a bounded LRU map of peer TCP-timestamp values.
// The recv hot path (recordPeerTSVal) inserts/updates one entry per
// inbound packet keyed by hash.IPAddr(srcIP, srcPort); the send hot
// path (loadPeerTSVal) reads one entry per outbound packet.
//
// Previously a sync.Map with no cap — entries grew unbounded over
// time because recordPeerTSVal fires for ANY inbound packet that
// the BPF filter passes, including peers that never complete the
// paqet handshake (scanners, random probes, traffic destined to
// other listeners). Each entry is small (~64 bytes) but a long-
// lived server slowly drifts.
//
// Eviction is approximate LRU: move-to-front on Store (recv-side
// writes) but NOT on Load (send-side reads). Skipping the read-side
// bump halves the lock cost on the heavier-contention send path
// without meaningfully degrading eviction quality — entries that
// the send side reads but recv side never refreshes are by
// definition stale (peer stopped sending), so eviction is correct.
type peerTSStore struct {
	mu  sync.Mutex
	m   map[uint64]*peerTSEntry
	lru *list.List
	cap int
}

type peerTSEntry struct {
	val  atomic.Uint32
	elem *list.Element // ptr back to LRU node holding the key
}

func newPeerTSStore(cap int) *peerTSStore {
	return &peerTSStore{
		m:   make(map[uint64]*peerTSEntry, cap/8), // start small, grow
		lru: list.New(),
		cap: cap,
	}
}

// load returns the most recently recorded value for key, or 0 if
// absent. Does NOT bump the LRU position — see type doc.
func (s *peerTSStore) load(key uint64) uint32 {
	s.mu.Lock()
	e, ok := s.m[key]
	s.mu.Unlock()
	if !ok {
		return 0
	}
	return e.val.Load()
}

// store sets the value for key. Inserts a new entry if absent;
// evicts LRU tail if at cap. Bumps the entry to LRU front on every
// call (existing entries get refreshed; new entries inserted at
// front).
func (s *peerTSStore) store(key uint64, val uint32) {
	if val == 0 {
		return // 0 is the "no timestamp" sentinel
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if e, ok := s.m[key]; ok {
		s.lru.MoveToFront(e.elem)
		e.val.Store(val)
		return
	}
	if s.lru.Len() >= s.cap {
		if tail := s.lru.Back(); tail != nil {
			evictKey := tail.Value.(uint64)
			delete(s.m, evictKey)
			s.lru.Remove(tail)
		}
	}
	elem := s.lru.PushFront(key)
	e := &peerTSEntry{elem: elem}
	e.val.Store(val)
	s.m[key] = e
}

// delete removes the entry. Called from sendHandle's clientTCPF
// eviction paths so dropping a smux session also cleans peerTS.
func (s *peerTSStore) delete(key uint64) {
	s.mu.Lock()
	if e, ok := s.m[key]; ok {
		s.lru.Remove(e.elem)
		delete(s.m, key)
	}
	s.mu.Unlock()
}

// len returns the current entry count. Test/diagnostic helper.
func (s *peerTSStore) len() int {
	s.mu.Lock()
	n := s.lru.Len()
	s.mu.Unlock()
	return n
}
