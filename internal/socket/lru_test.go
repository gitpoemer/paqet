package socket

import (
	"sync"
	"testing"
)

func TestPeerTSStore_LoadMiss(t *testing.T) {
	s := newPeerTSStore(8)
	if v := s.load(42); v != 0 {
		t.Fatalf("load on empty = %d, want 0", v)
	}
}

func TestPeerTSStore_StoreAndLoad(t *testing.T) {
	s := newPeerTSStore(8)
	s.store(1, 0xCAFE)
	s.store(2, 0xBABE)
	if v := s.load(1); v != 0xCAFE {
		t.Fatalf("load(1) = %x, want CAFE", v)
	}
	if v := s.load(2); v != 0xBABE {
		t.Fatalf("load(2) = %x, want BABE", v)
	}
}

func TestPeerTSStore_StoreUpdates(t *testing.T) {
	s := newPeerTSStore(8)
	s.store(1, 0x1111)
	s.store(1, 0x2222)
	if v := s.load(1); v != 0x2222 {
		t.Fatalf("load after update = %x, want 2222", v)
	}
	if n := s.len(); n != 1 {
		t.Fatalf("len = %d, want 1 (update should not insert)", n)
	}
}

func TestPeerTSStore_ZeroValueIgnored(t *testing.T) {
	s := newPeerTSStore(8)
	s.store(1, 0xABCD)
	s.store(1, 0) // sentinel
	if v := s.load(1); v != 0xABCD {
		t.Fatalf("zero overwrote existing: %x", v)
	}
	s.store(2, 0) // brand-new key with zero value — should NOT insert
	if v := s.load(2); v != 0 {
		t.Fatalf("zero-value store created an entry: %x", v)
	}
	if n := s.len(); n != 1 {
		t.Fatalf("len = %d, want 1", n)
	}
}

// TestPeerTSStore_EvictsOldestOnCap is THE bounded-LRU regression test.
// Fills the store past capacity, asserts size stays at cap, and that the
// oldest entry is the one evicted.
func TestPeerTSStore_EvictsOldestOnCap(t *testing.T) {
	const cap = 4
	s := newPeerTSStore(cap)

	for i := uint64(1); i <= 6; i++ {
		s.store(i, uint32(i))
	}

	if n := s.len(); n != cap {
		t.Fatalf("post-overflow len = %d, want cap %d", n, cap)
	}

	// Oldest 2 entries (keys 1, 2) should have been evicted.
	for k := uint64(1); k <= 2; k++ {
		if v := s.load(k); v != 0 {
			t.Fatalf("key %d should be evicted but load returned %x", k, v)
		}
	}
	// Newest 4 entries (keys 3..6) should remain.
	for k := uint64(3); k <= 6; k++ {
		if v := s.load(k); v != uint32(k) {
			t.Fatalf("key %d should be present, got %x", k, v)
		}
	}
}

// TestPeerTSStore_LRU_MovesToFrontOnUpdate: an entry refreshed (the
// recv hot path on every inbound packet) must move to LRU front so a
// later eviction doesn't kill an active peer.
func TestPeerTSStore_LRU_MovesToFrontOnUpdate(t *testing.T) {
	const cap = 3
	s := newPeerTSStore(cap)

	s.store(1, 0x11) // back of LRU
	s.store(2, 0x22)
	s.store(3, 0x33) // front

	// Refresh key 1; should move it to front.
	s.store(1, 0x1111)

	// Insert a new key; the LRU tail (now key 2) should be evicted —
	// NOT key 1 (which we just refreshed).
	s.store(4, 0x44)

	if v := s.load(2); v != 0 {
		t.Fatalf("key 2 should have been evicted; load=%x", v)
	}
	if v := s.load(1); v != 0x1111 {
		t.Fatalf("key 1 should still be present at 0x1111; got %x", v)
	}
}

func TestPeerTSStore_Delete(t *testing.T) {
	s := newPeerTSStore(8)
	s.store(1, 0xAA)
	s.delete(1)
	if v := s.load(1); v != 0 {
		t.Fatalf("post-delete load = %x, want 0", v)
	}
	if n := s.len(); n != 0 {
		t.Fatalf("len = %d after delete, want 0", n)
	}
	// Delete of missing key is a no-op.
	s.delete(99)
	if n := s.len(); n != 0 {
		t.Fatalf("len = %d, want 0", n)
	}
}

// TestPeerTSStore_ConcurrentStress runs many goroutines store/load
// across overlapping key sets at cap saturation. Catches lock-ordering
// or map-corruption bugs in the LRU bookkeeping under contention.
func TestPeerTSStore_ConcurrentStress(t *testing.T) {
	const cap = 100
	s := newPeerTSStore(cap)

	const goroutines = 16
	const opsPerGoroutine = 1000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				k := uint64((seed*opsPerGoroutine + i) % (cap * 4))
				if i%2 == 0 {
					s.store(k+1, uint32(i+1))
				} else {
					_ = s.load(k + 1)
				}
			}
		}(g)
	}
	wg.Wait()

	// After contention, len must be bounded by cap.
	if n := s.len(); n > cap {
		t.Fatalf("len = %d exceeds cap %d", n, cap)
	}
}
