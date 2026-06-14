package buffer

import (
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// In these tests, the conn-side simulates the local TCP socket (browser,
// SOCKS5 client) and the strm-side simulates the smux stream to the
// remote peer. RelayBidi runs on (connRelay, strmRelay); the *Local /
// *Peer halves of each pair are the test driver's handles for closing
// or feeding data.
//
// Reminder of which goroutine reads what (from relay.go):
//   - bg     = CopyT(conn, strm)  → reads strm, writes conn  (server→local direction)
//   - inline = CopyT(strm, conn)  → reads conn, writes strm  (local→server direction)
//
// Therefore:
//   - "local app closes its TCP conn" → connRelay.Read EOFs → inline returns first
//   - "remote peer closes the smux stream" → strmRelay.Read EOFs → bg returns first

func pipePair() (a, b net.Conn) { return net.Pipe() }

func init() {
	// RelayBidi → CopyT requires TPool to be sized; production code does
	// this via buffer.Initialize() at startup. Match that here.
	if TPool == 0 {
		Initialize(4096, 4096)
	}
}

// withTimeout asserts that fn returns within d. Fails the test if it
// hangs — the regression-catch for the bidi-copy deadlock.
func withTimeout(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("RelayBidi did not return within %s — bidi-copy deadlock regressed", d)
	}
}

// TestRelayBidi_LocalClosesConn_BGUnblocks is the primary regression
// test for the alpha.27→alpha.28 fix. The local TCP app closes its conn
// first (the dominant real-world pattern: browser closing after a short
// HTTP request). Inline's conn.Read EOFs. The fix must close strm so
// bg's strm.Read unblocks; otherwise bg hangs until the smux peer
// happens to close from its side.
func TestRelayBidi_LocalClosesConn_BGUnblocks(t *testing.T) {
	connRelay, connLocal := pipePair()
	strmRelay, strmPeer := pipePair()

	// strmPeer never closes and never writes — it just sits. With the
	// bug, bg's strm.Read on strmRelay would block forever waiting for
	// strmPeer to do something.
	go connLocal.Close()

	withTimeout(t, 2*time.Second, func() {
		_, _ = RelayBidi(connRelay, strmRelay)
	})

	strmPeer.Close()
}

// TestRelayBidi_PeerClosesStrm_InlineUnblocks is the symmetric case:
// the remote peer closes the smux stream first. bg's strm.Read EOFs.
// The fix must close conn so inline's conn.Read unblocks.
func TestRelayBidi_PeerClosesStrm_InlineUnblocks(t *testing.T) {
	connRelay, connLocal := pipePair()
	strmRelay, strmPeer := pipePair()

	go strmPeer.Close()

	withTimeout(t, 2*time.Second, func() {
		_, _ = RelayBidi(connRelay, strmRelay)
	})

	connLocal.Close()
}

// TestRelayBidi_DataFlowsBothWays_ThenCloseClean: full happy path.
// Local writes, peer echoes back, both sides close. Verifies the
// payload roundtrips through the relay correctly and that clean Close
// on both ends returns without hanging.
func TestRelayBidi_DataFlowsBothWays_ThenCloseClean(t *testing.T) {
	connRelay, connLocal := pipePair()
	strmRelay, strmPeer := pipePair()

	const msg = "hello-paqet"

	// Peer echoes: anything from strm side it sends back.
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		io.Copy(strmPeer, strmPeer)
	}()

	// Local writes msg, reads echoed copy back, then closes.
	gotCh := make(chan []byte, 1)
	go func() {
		_, _ = connLocal.Write([]byte(msg))
		buf := make([]byte, len(msg))
		_, err := io.ReadFull(connLocal, buf)
		if err != nil {
			t.Errorf("local read failed: %v", err)
		}
		gotCh <- buf
		connLocal.Close()
	}()

	withTimeout(t, 3*time.Second, func() {
		_, _ = RelayBidi(connRelay, strmRelay)
	})

	select {
	case got := <-gotCh:
		if string(got) != msg {
			t.Fatalf("echoed payload mismatch: got %q want %q", got, msg)
		}
	default:
		t.Fatal("local goroutine never produced echoed payload")
	}

	strmPeer.Close()
	<-echoDone
}

// TestRelayBidi_CloseCallsAreIdempotent: callers may also have
// `defer strm.Close()` and `defer conn.Close()`. After RelayBidi
// returns, the helper has already closed both endpoints — caller's
// deferred Close must not panic and must return cleanly.
func TestRelayBidi_CloseCallsAreIdempotent(t *testing.T) {
	connRelay, connLocal := pipePair()
	strmRelay, strmPeer := pipePair()

	go connLocal.Close()

	withTimeout(t, 2*time.Second, func() {
		_, _ = RelayBidi(connRelay, strmRelay)
	})

	if err := connRelay.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second connRelay.Close returned unexpected err: %v", err)
	}
	if err := strmRelay.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second strmRelay.Close returned unexpected err: %v", err)
	}

	strmPeer.Close()
}

// blockingCloser is a ReadWriteCloser whose Read blocks until Close is
// called. Lets us simulate a smux stream that has no traffic and never
// EOFs from its peer side — the case where ONLY the helper's internal
// Close can break the deadlock (net.Pipe close-propagation isn't
// involved).
type blockingCloser struct {
	closed chan struct{}
	once   sync.Once
	reads  atomic.Int32
	writes atomic.Int32
}

func newBlockingCloser() *blockingCloser {
	return &blockingCloser{closed: make(chan struct{})}
}

func (b *blockingCloser) Read(p []byte) (int, error) {
	b.reads.Add(1)
	<-b.closed
	return 0, io.EOF
}

func (b *blockingCloser) Write(p []byte) (int, error) {
	b.writes.Add(1)
	select {
	case <-b.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(p), nil
	}
}

func (b *blockingCloser) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

// TestRelayBidi_StrmBlocksOnRead_LocalCloseTriggersStrmClose: the
// hardest deadlock case. strm has no traffic in either direction — bg
// blocks on strm.Read. Local app closes conn → inline returns. RelayBidi
// must close strm to unblock bg. Without the fix, this test deadlocks.
func TestRelayBidi_StrmBlocksOnRead_LocalCloseTriggersStrmClose(t *testing.T) {
	strm := newBlockingCloser()
	connRelay, connLocal := pipePair()

	go connLocal.Close() // inline returns first

	withTimeout(t, 2*time.Second, func() {
		_, _ = RelayBidi(connRelay, strm)
	})

	if strm.reads.Load() == 0 {
		t.Fatal("bg goroutine never even attempted strm.Read — test plumbing broken")
	}
}

// TestRelayBidi_ConnBlocksOnRead_PeerCloseTriggersConnClose: the
// symmetric hardest case. conn has no traffic, peer closes strm first
// → bg returns. RelayBidi must close conn so inline (blocked on
// conn.Read) unblocks.
func TestRelayBidi_ConnBlocksOnRead_PeerCloseTriggersConnClose(t *testing.T) {
	conn := newBlockingCloser()
	strmRelay, strmPeer := pipePair()

	go strmPeer.Close() // bg returns first

	withTimeout(t, 2*time.Second, func() {
		_, _ = RelayBidi(conn, strmRelay)
	})

	if conn.reads.Load() == 0 {
		t.Fatal("inline goroutine never even attempted conn.Read — test plumbing broken")
	}
}

// TestRelayBidi_NoLingeringGoroutine: after RelayBidi returns, the
// spawned bg goroutine must not still be running. We can't observe
// goroutines directly without runtime hacks; instead we observe the
// effect — repeat 200 iterations, the test must complete promptly
// regardless of how many runs accumulate.
func TestRelayBidi_NoLingeringGoroutine(t *testing.T) {
	for i := 0; i < 200; i++ {
		connRelay, connLocal := pipePair()
		strm := newBlockingCloser()
		go connLocal.Close()
		_, _ = RelayBidi(connRelay, strm)
	}
}
