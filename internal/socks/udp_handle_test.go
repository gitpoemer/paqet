package socks

import (
	"net"
	"paqet/internal/tnet"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeUDPStrm is a minimal tnet.Strm that satisfies net.Conn enough
// for the UDP relay code paths without needing a real smux.
type fakeUDPStrm struct {
	id        int
	closed    atomic.Bool
	readBlock chan struct{}
}

func newFakeUDPStrm(id int) *fakeUDPStrm {
	return &fakeUDPStrm{id: id, readBlock: make(chan struct{})}
}

func (f *fakeUDPStrm) Read(p []byte) (int, error) {
	<-f.readBlock
	return 0, net.ErrClosed
}
func (f *fakeUDPStrm) Write(p []byte) (int, error) {
	if f.closed.Load() {
		return 0, net.ErrClosed
	}
	return len(p), nil
}
func (f *fakeUDPStrm) Close() error {
	if f.closed.CompareAndSwap(false, true) {
		close(f.readBlock)
	}
	return nil
}
func (f *fakeUDPStrm) LocalAddr() net.Addr                { return &net.UDPAddr{} }
func (f *fakeUDPStrm) RemoteAddr() net.Addr               { return &net.UDPAddr{} }
func (f *fakeUDPStrm) SetDeadline(t time.Time) error      { return nil }
func (f *fakeUDPStrm) SetReadDeadline(t time.Time) error  { return nil }
func (f *fakeUDPStrm) SetWriteDeadline(t time.Time) error { return nil }
func (f *fakeUDPStrm) SID() int                           { return f.id }

// fakeUDPClient mimics *client.Client's UDP / CloseUDP methods plus
// an internal "pool" so tests can check whether CloseUDP was called
// (and therefore whether the pool entry was actually freed).
type fakeUDPClient struct {
	mu       sync.Mutex
	pool     map[uint64]*fakeUDPStrm // active entries
	nextKey  uint64
	closeLog []uint64 // keys for which CloseUDP fired
}

func newFakeUDPClient() *fakeUDPClient {
	return &fakeUDPClient{pool: make(map[uint64]*fakeUDPStrm)}
}

func (c *fakeUDPClient) UDP(lAddr, tAddr string) (tnet.Strm, bool, uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextKey++
	k := c.nextKey
	s := newFakeUDPStrm(int(k))
	c.pool[k] = s
	return s, true, k, nil
}

func (c *fakeUDPClient) CloseUDP(key uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeLog = append(c.closeLog, key)
	if s, ok := c.pool[key]; ok {
		s.Close()
		delete(c.pool, key)
	}
	return nil
}

func (c *fakeUDPClient) PoolSize() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pool)
}

func (c *fakeUDPClient) CloseLog() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]uint64, len(c.closeLog))
	copy(out, c.closeLog)
	return out
}

// TestUDPStreamSet_CloseOne_CallsCloseUDP is the regression test for
// the alpha.30 fix. Prior to the fix, closeOne released the local
// map entry but never called client.CloseUDP — so the CLIENT-wide
// udpPool accumulated stale Closed-strm entries, and a repeat
// lookup for the same (src, target) pair returned the dead pointer.
// The dominant real-world trigger is QUIC / MTProto-style long-lived
// UDP flows from a fixed client port: as paqet rotates the underlying
// stream (deadline, KCP loss, smux session restart), the user-facing
// connection breaks "after a while" because subsequent datagrams to
// the same target keep landing on a dead stream.
func TestUDPStreamSet_CloseOne_CallsCloseUDP(t *testing.T) {
	c := newFakeUDPClient()
	s := &udpStreamSet{client: c, entries: make(map[string]*udpStreamEntry)}

	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	dest := AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4(8, 8, 8, 8).To4(), Port: 53}

	entry, isNew, err := s.getOrCreate(src, dest.String(), dest)
	if err != nil {
		t.Fatal(err)
	}
	if !isNew {
		t.Fatal("expected isNew=true on first call")
	}
	if c.PoolSize() != 1 {
		t.Fatalf("client pool size = %d, want 1", c.PoolSize())
	}

	// Simulate the stream dying — reader goroutine calls closeOne(key).
	s.closeOne(entry.key)

	if c.PoolSize() != 0 {
		t.Fatalf("client pool size = %d after closeOne, want 0 — CloseUDP not called", c.PoolSize())
	}
	log := c.CloseLog()
	if len(log) != 1 || log[0] != entry.clientKey {
		t.Fatalf("CloseLog = %v, want [%d]", log, entry.clientKey)
	}
}

// TestUDPStreamSet_CloseAll_CleansClientPool is the symmetric case
// for the per-association teardown path (TCP control conn closes).
// Each entry must hit CloseUDP, not just strm.Close.
func TestUDPStreamSet_CloseAll_CleansClientPool(t *testing.T) {
	c := newFakeUDPClient()
	s := &udpStreamSet{client: c, entries: make(map[string]*udpStreamEntry)}

	for i := 0; i < 5; i++ {
		src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000 + i}
		dest := AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4(8, 8, 8, 8).To4(), Port: uint16(53 + i)}
		_, _, err := s.getOrCreate(src, dest.String(), dest)
		if err != nil {
			t.Fatal(err)
		}
	}
	if c.PoolSize() != 5 {
		t.Fatalf("expected 5 pool entries before closeAll, got %d", c.PoolSize())
	}

	s.closeAll()

	if c.PoolSize() != 0 {
		t.Fatalf("client pool size = %d after closeAll, want 0", c.PoolSize())
	}
	if len(c.CloseLog()) != 5 {
		t.Fatalf("CloseUDP fired %d times, want 5", len(c.CloseLog()))
	}
}

// TestUDPStreamSet_GetOrCreate_RaceLoser_CleansClientPool: when two
// goroutines race to create the same (src, target) stream, the loser
// must call CloseUDP on its allocated (now-orphaned) entry. Without
// this, every race-losing allocation leaks a client-pool entry.
func TestUDPStreamSet_GetOrCreate_RaceLoser_CleansClientPool(t *testing.T) {
	c := newFakeUDPClient()
	s := &udpStreamSet{client: c, entries: make(map[string]*udpStreamEntry)}

	src := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5000}
	target := "8.8.8.8:53"
	dest := AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4(8, 8, 8, 8).To4(), Port: 53}

	// Force a race by pre-populating the local map with a "winner"
	// entry, then calling getOrCreate which will:
	//   1. miss the entries map on first peek
	//   2. allocate a strm via client.UDP (pool size becomes 2)
	//   3. re-check map under lock, find the winner, drop ours
	//   4. (with the fix) call CloseUDP on our orphaned key
	winnerStrm := newFakeUDPStrm(999)
	winnerEntry := &udpStreamEntry{
		key: src.String() + "|" + target, clientKey: 999, strm: winnerStrm,
	}
	// We need to insert the winner BETWEEN the peek-without-lock and
	// the re-check-under-lock. Easiest: pre-insert, since the peek
	// path returns immediately on hit and won't hit getOrCreate's
	// alloc step at all. So we need a slightly different setup.
	//
	// Trick: call getOrCreate concurrently from N goroutines. Exactly
	// one wins, N-1 lose. With the fix, the client pool stays at 1.
	// Without the fix, the pool ends up at N.
	_ = winnerEntry

	const N = 8
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, _, err := s.getOrCreate(src, target, dest)
			if err != nil {
				t.Errorf("getOrCreate: %v", err)
			}
		}()
	}
	wg.Wait()

	// Exactly 1 winning entry should remain in the client pool.
	if c.PoolSize() != 1 {
		t.Fatalf("client pool size = %d after race, want 1 — race-loser leak", c.PoolSize())
	}
}
