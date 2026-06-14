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

// netConnAdapter adapts a net.Conn into a UDPEndpoint (which is exactly
// net.Conn minus the bits we don't use). Used by tests built on
// net.Pipe-like fakes.
type netConnAdapter struct{ net.Conn }

// idleSrcConn is a UDPEndpoint that always blocks Read until either
// SetReadDeadline fires (returning a Timeout error) or Close fires.
// Models a fully-idle UDP endpoint — both sides of a real relay would
// be in this state when no app traffic flows.
type idleSrcConn struct {
	mu       sync.Mutex
	deadline time.Time
	closed   chan struct{}
	closeOnce sync.Once
	reads    atomic.Int32
	writes   atomic.Int32
}

func newIdleSrcConn() *idleSrcConn { return &idleSrcConn{closed: make(chan struct{})} }

func (c *idleSrcConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()
	var timer *time.Timer
	var deadlineCh <-chan time.Time
	if !d.IsZero() {
		remaining := time.Until(d)
		if remaining <= 0 {
			return 0, idleTimeoutErr{}
		}
		timer = time.NewTimer(remaining)
		defer timer.Stop()
		deadlineCh = timer.C
	}
	select {
	case <-c.closed:
		return 0, io.EOF
	case <-deadlineCh:
		return 0, idleTimeoutErr{}
	}
}

func (c *idleSrcConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(p), nil
	}
}

func (c *idleSrcConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *idleSrcConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

// idleTimeoutErr satisfies net.Error with Timeout()=true so the relay
// treats it as a clean idle close, not an error to surface.
type idleTimeoutErr struct{}

func (idleTimeoutErr) Error() string { return "i/o timeout" }
func (idleTimeoutErr) Timeout() bool { return true }
func (idleTimeoutErr) Temporary() bool { return true }

// --- the actual regression test ---

// TestRelayUDPBidi_BothIdle_TimesOut is the alpha.31 regression test.
// Two endpoints with NO traffic in either direction. Without the idle
// timeout (the pre-alpha.31 production code path), the relay would
// sit forever — 486 server goroutines reproduced exactly this in the
// wild. With the fix, it returns within idleTimeout + a small slack.
func TestRelayUDPBidi_BothIdle_TimesOut(t *testing.T) {
	strm := newIdleSrcConn()
	conn := newIdleSrcConn()

	const idleTimeout = 100 * time.Millisecond
	start := time.Now()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = RelayUDPBidi(strm, conn, idleTimeout)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RelayUDPBidi did not return within 2s — idle-timeout regression")
	}

	elapsed := time.Since(start)
	if elapsed < idleTimeout {
		t.Fatalf("returned too fast (%s) — idle timeout shorter than expected", elapsed)
	}
	if elapsed > idleTimeout*5 {
		t.Fatalf("returned too slow (%s) — timeout schedule isn't tight", elapsed)
	}
}

// activeSrcConn produces a stream of small payloads at a fixed
// interval, simulating an active UDP flow (DNS keepalive,
// long-running game, QUIC heartbeat). Each Read returns one byte
// after the interval elapses, refreshing the relay's idle timer.
type activeSrcConn struct {
	interval  time.Duration
	deadline  time.Time
	mu        sync.Mutex
	closed    chan struct{}
	closeOnce sync.Once
	sent      atomic.Int32
}

func newActiveSrcConn(interval time.Duration) *activeSrcConn {
	return &activeSrcConn{interval: interval, closed: make(chan struct{})}
}

func (c *activeSrcConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	d := c.deadline
	c.mu.Unlock()

	var deadlineCh <-chan time.Time
	if !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadlineCh = timer.C
	}

	select {
	case <-c.closed:
		return 0, io.EOF
	case <-time.After(c.interval):
		p[0] = 0x42
		c.sent.Add(1)
		return 1, nil
	case <-deadlineCh:
		return 0, idleTimeoutErr{}
	}
}

func (c *activeSrcConn) Write(p []byte) (int, error) {
	select {
	case <-c.closed:
		return 0, io.ErrClosedPipe
	default:
		return len(p), nil
	}
}

func (c *activeSrcConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return nil
}

func (c *activeSrcConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.deadline = t
	c.mu.Unlock()
	return nil
}

// TestRelayUDPBidi_ActiveTrafficKeepsAlive: a session with steady
// traffic at a shorter interval than idleTimeout must stay alive past
// idleTimeout. Catches a regression where the timeout is reset to
// absolute (instead of relative-to-last-read) — that would kill
// active sessions on the first interval boundary.
func TestRelayUDPBidi_ActiveTrafficKeepsAlive(t *testing.T) {
	const idleTimeout = 200 * time.Millisecond
	const trafficInterval = 50 * time.Millisecond
	const observeFor = 500 * time.Millisecond

	strm := newActiveSrcConn(trafficInterval)
	conn := newActiveSrcConn(trafficInterval)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = RelayUDPBidi(strm, conn, idleTimeout)
	}()

	time.Sleep(observeFor)
	// Both sides have been delivering data every 50ms; idleTimeout
	// is 200ms; the relay should still be running.
	select {
	case <-done:
		t.Fatal("relay exited despite continuous traffic")
	default:
	}

	// Now stop the traffic and verify the relay drains.
	strm.Close()
	conn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("relay did not exit after both sides closed")
	}

	if strm.sent.Load() < 5 || conn.sent.Load() < 5 {
		t.Fatalf("expected steady traffic (>=5 each), got strm=%d conn=%d", strm.sent.Load(), conn.sent.Load())
	}
}

// TestRelayUDPBidi_BGExitsFirst_ClosesBoth: one endpoint errors first;
// the other (blocked on idle Read) must unblock via the helper's
// internal Close, not via its own deadline. Mirrors the alpha.28 TCP
// bidi-copy fix verified for UDP.
func TestRelayUDPBidi_BGExitsFirst_ClosesBoth(t *testing.T) {
	strm := newIdleSrcConn()
	conn := newIdleSrcConn()

	// Close strm immediately → bg's CopyU(conn, strm) reads from strm,
	// gets EOF, returns. bg then closes BOTH strm and conn. inline,
	// which was idle-Reading conn, gets EOF via conn.Close.
	go strm.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = RelayUDPBidi(strm, conn, 30*time.Second) // long timeout to prove the close-chain works
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RelayUDPBidi did not return — inline didn't unblock when bg closed conn")
	}
}

// TestRelayUDPBidi_InlineExitsFirst_ClosesBoth: symmetric to the above
// — close conn first, bg reading strm must unblock.
func TestRelayUDPBidi_InlineExitsFirst_ClosesBoth(t *testing.T) {
	strm := newIdleSrcConn()
	conn := newIdleSrcConn()

	go conn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = RelayUDPBidi(strm, conn, 30*time.Second)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("RelayUDPBidi did not return — bg didn't unblock when inline closed strm")
	}
}

// TestRelayUDPBidi_NoGoroutineLeak runs many idle-timeout cycles in
// sequence. If the spawned bg goroutine leaked on any iteration, the
// test would take a very long time or fail. The 50-iter loop with
// 30ms per iter is ~1.5s wall-clock total — bounded.
func TestRelayUDPBidi_NoGoroutineLeak(t *testing.T) {
	for i := 0; i < 50; i++ {
		strm := newIdleSrcConn()
		conn := newIdleSrcConn()
		_, _ = RelayUDPBidi(strm, conn, 30*time.Millisecond)
	}
}

// TestRelayUDPBidi_ReturnsTimeoutNil: idle timeout fires → both
// directions return nil (it's a clean close, not an error). Catches
// a regression where the timeout would surface as a net.Error to
// the caller, who'd log it as "UDP stream failed" pointlessly.
func TestRelayUDPBidi_ReturnsTimeoutNil(t *testing.T) {
	strm := newIdleSrcConn()
	conn := newIdleSrcConn()

	inlineErr, bgErr := RelayUDPBidi(strm, conn, 30*time.Millisecond)

	if inlineErr != nil {
		t.Fatalf("inlineErr = %v, want nil (clean idle close)", inlineErr)
	}
	if bgErr != nil {
		t.Fatalf("bgErr = %v, want nil (clean idle close)", bgErr)
	}
}

// TestRelayUDPBidi_RealNetUDPConn: integration test using actual
// net.UDPConn endpoints. Catches anything the fakes might not model
// correctly (e.g., real SetReadDeadline semantics, real Timeout()
// error type).
func TestRelayUDPBidi_RealNetUDPConn(t *testing.T) {
	conn1, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn1.Close()

	conn2, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()

	const idleTimeout = 100 * time.Millisecond
	start := time.Now()

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = RelayUDPBidi(conn1, conn2, idleTimeout)
	}()

	select {
	case <-done:
		elapsed := time.Since(start)
		if elapsed < idleTimeout || elapsed > idleTimeout*5 {
			t.Fatalf("idle timeout fired at %s, want %s±slack", elapsed, idleTimeout)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("real UDPConn relay did not idle-timeout")
	}
}

// ensure errors.As recognizes net.Error from a real net stack timeout
func TestIsTimeoutDetection(t *testing.T) {
	// Concrete net.Error from net.UDPConn idle deadline.
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
	buf := make([]byte, 16)
	_, _, readErr := c.ReadFromUDP(buf)
	if readErr == nil {
		t.Fatal("expected deadline error from idle UDPConn")
	}
	var ne net.Error
	if !errors.As(readErr, &ne) || !ne.Timeout() {
		t.Fatalf("real-world error %v doesn't satisfy net.Error+Timeout, would not be treated as idle close", readErr)
	}
}
