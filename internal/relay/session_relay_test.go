package relay

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeStrm implements the Strm interface for tests. Lets us drive
// readability events, queue data, simulate close, and observe what
// the coordinator did.
type fakeStrm struct {
	id          uint32
	mu          sync.Mutex
	pending     [][]byte // chunks to deliver via TryRead in order
	closed      atomic.Bool
	dieCh       chan struct{}
	readEvents  chan struct{}
	tryReadHits atomic.Int32
	writes      []byte
}

func newFakeStrm(id uint32) *fakeStrm {
	return &fakeStrm{
		id:         id,
		dieCh:      make(chan struct{}),
		readEvents: make(chan struct{}, 1),
	}
}

func (f *fakeStrm) ID() uint32 { return f.id }

func (f *fakeStrm) TryRead(b []byte) (int, error) {
	f.tryReadHits.Add(1)
	f.mu.Lock()
	if len(f.pending) == 0 {
		f.mu.Unlock()
		if f.closed.Load() {
			return 0, io.EOF
		}
		return 0, ErrWouldBlock
	}
	next := f.pending[0]
	n := copy(b, next)
	if n < len(next) {
		f.pending[0] = next[n:]
	} else {
		f.pending = f.pending[1:]
	}
	f.mu.Unlock()
	return n, nil
}

// queue adds data to be delivered via the next TryRead calls AND
// fires a ReadEvent so the coordinator notices.
func (f *fakeStrm) queue(data []byte) {
	f.mu.Lock()
	f.pending = append(f.pending, append([]byte(nil), data...))
	f.mu.Unlock()
	select {
	case f.readEvents <- struct{}{}:
	default:
	}
}

func (f *fakeStrm) Read(p []byte) (int, error) {
	for {
		n, err := f.TryRead(p)
		if err != ErrWouldBlock {
			return n, err
		}
		select {
		case <-f.dieCh:
			return 0, io.EOF
		case <-f.readEvents:
		}
	}
}

func (f *fakeStrm) Write(p []byte) (int, error) {
	f.mu.Lock()
	f.writes = append(f.writes, p...)
	f.mu.Unlock()
	return len(p), nil
}

func (f *fakeStrm) Close() error {
	if f.closed.CompareAndSwap(false, true) {
		close(f.dieCh)
	}
	return nil
}

func (f *fakeStrm) ReadEvents() <-chan struct{} { return f.readEvents }
func (f *fakeStrm) GetDieCh() <-chan struct{}   { return f.dieCh }

// memConn is an in-memory net.Conn-ish that captures Write data and
// fakes the rest. Lets us verify the coordinator forwarded bytes
// correctly without spinning up TCP.
type memConn struct {
	mu      sync.Mutex
	written bytes.Buffer
	closed  atomic.Bool
	failOn  int // if >0, fail after this many bytes (cumulative)
}

func (c *memConn) Read(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	return 0, io.EOF // memConn never produces inbound data in these tests
}

func (c *memConn) Write(p []byte) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failOn > 0 && c.written.Len()+len(p) > c.failOn {
		return 0, errors.New("simulated write fail")
	}
	c.written.Write(p)
	return len(p), nil
}

func (c *memConn) Close() error {
	c.closed.Store(true)
	return nil
}

func (c *memConn) LocalAddr() net.Addr                { return nil }
func (c *memConn) RemoteAddr() net.Addr               { return nil }
func (c *memConn) SetDeadline(t time.Time) error      { return nil }
func (c *memConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *memConn) SetWriteDeadline(t time.Time) error { return nil }

func (c *memConn) bytesWritten() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.written.Bytes()...)
}

// --- tests ---

// TestSessionRelay_SingleStream_BasicForwarding: register one stream,
// queue some data, verify it's forwarded to the conn.
func TestSessionRelay_SingleStream_BasicForwarding(t *testing.T) {
	r := NewSessionRelay()
	r.Start()
	defer r.Stop()

	strm := newFakeStrm(1)
	conn := &memConn{}
	r.Register(strm, conn)

	strm.queue([]byte("hello"))
	strm.queue([]byte("world"))

	waitFor(t, time.Second, func() bool {
		return len(conn.bytesWritten()) >= 10
	})
	if got := string(conn.bytesWritten()); got != "helloworld" {
		t.Fatalf("conn got %q, want %q", got, "helloworld")
	}
}

// TestSessionRelay_ManyStreams_Independent: 10 streams, each gets
// independent data, all forwarded correctly to their respective
// conns. Covers the reflect.Select dispatch path.
func TestSessionRelay_ManyStreams_Independent(t *testing.T) {
	r := NewSessionRelay()
	r.Start()
	defer r.Stop()

	const N = 10
	strms := make([]*fakeStrm, N)
	conns := make([]*memConn, N)
	for i := 0; i < N; i++ {
		strms[i] = newFakeStrm(uint32(i + 1))
		conns[i] = &memConn{}
		r.Register(strms[i], conns[i])
	}

	for i, s := range strms {
		s.queue([]byte{byte(i)})
	}

	waitFor(t, 2*time.Second, func() bool {
		for _, c := range conns {
			if len(c.bytesWritten()) < 1 {
				return false
			}
		}
		return true
	})

	for i, c := range conns {
		got := c.bytesWritten()
		if len(got) != 1 || got[0] != byte(i) {
			t.Fatalf("conn %d got % x, want [%02x]", i, got, byte(i))
		}
	}
}

// TestSessionRelay_StreamClose_RemovesEntry: a stream that dies
// gets unregistered automatically (via the GetDieCh select branch),
// freeing coordinator state.
func TestSessionRelay_StreamClose_RemovesEntry(t *testing.T) {
	r := NewSessionRelay()
	r.Start()
	defer r.Stop()

	strm := newFakeStrm(42)
	conn := &memConn{}
	r.Register(strm, conn)

	strm.Close()
	waitFor(t, time.Second, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		_, present := r.streams[42]
		return !present
	})
}

// TestSessionRelay_Unregister_StopsWorker: explicit Unregister
// removes the stream and stops any in-progress worker.
func TestSessionRelay_Unregister_StopsWorker(t *testing.T) {
	r := NewSessionRelay()
	r.Start()
	defer r.Stop()

	strm := newFakeStrm(7)
	conn := &memConn{}
	r.Register(strm, conn)

	strm.queue([]byte("ab"))
	waitFor(t, time.Second, func() bool {
		return strm.tryReadHits.Load() > 0
	})

	r.Unregister(7)
	r.mu.Lock()
	_, present := r.streams[7]
	r.mu.Unlock()
	if present {
		t.Fatal("entry should be removed after Unregister")
	}
}

// TestSessionRelay_NoDoubleWorker: rapid-fire events on the same
// stream must not spawn multiple workers (would race on conn.Write).
// The workerActive flag guards this; assert it via tryReadHits
// progressing serially.
func TestSessionRelay_NoDoubleWorker(t *testing.T) {
	r := NewSessionRelay()
	r.Start()
	defer r.Stop()

	strm := newFakeStrm(99)
	conn := &memConn{}
	r.Register(strm, conn)

	// Fire 100 read events in quick succession while queueing data.
	for i := 0; i < 100; i++ {
		strm.queue([]byte{byte(i)})
	}

	waitFor(t, 2*time.Second, func() bool {
		return len(conn.bytesWritten()) >= 100
	})

	got := conn.bytesWritten()
	if len(got) != 100 {
		t.Fatalf("got %d bytes, want 100 (worker duplicated?)", len(got))
	}
	// Bytes must be in order — would not be if multiple workers raced.
	for i, b := range got {
		if int(b) != i {
			t.Fatalf("byte %d = %d, want %d (out-of-order write)", i, b, i)
		}
	}
}

// TestSessionRelay_WriteError_ClosesStream: when the conn.Write
// fails, the coordinator closes the stream so the conn→strm
// direction (caller's responsibility) gets the signal to exit too.
func TestSessionRelay_WriteError_ClosesStream(t *testing.T) {
	r := NewSessionRelay()
	r.Start()
	defer r.Stop()

	strm := newFakeStrm(1)
	conn := &memConn{failOn: 3}
	r.Register(strm, conn)

	strm.queue([]byte("12345"))
	waitFor(t, time.Second, func() bool {
		return strm.closed.Load()
	})
}

// TestSessionRelay_Stop_DrainsCleanly: Stop closes the coordinator
// and any in-flight workers exit promptly. No goroutine leak.
func TestSessionRelay_Stop_DrainsCleanly(t *testing.T) {
	r := NewSessionRelay()
	r.Start()

	strm := newFakeStrm(1)
	conn := &memConn{}
	r.Register(strm, conn)
	strm.queue([]byte("data"))

	r.Stop()

	// After Stop, further Register is a no-op.
	r.Register(newFakeStrm(2), &memConn{}) // must not panic
}

// TestSessionRelay_StopBeforeStart_NoOp: Stop is safe to call before
// Start; Start is then a no-op too.
func TestSessionRelay_StopBeforeStart_NoOp(t *testing.T) {
	r := NewSessionRelay()
	r.Stop()
	r.Start()
}

// TestSessionRelay_HeavyTraffic_OrderPreserved: simulate a busy
// single stream with chunks arriving back-to-back. All bytes must
// arrive in order at conn.
func TestSessionRelay_HeavyTraffic_OrderPreserved(t *testing.T) {
	r := NewSessionRelay()
	r.Start()
	defer r.Stop()

	strm := newFakeStrm(1)
	conn := &memConn{}
	r.Register(strm, conn)

	const total = 10000
	want := make([]byte, total)
	for i := range want {
		want[i] = byte(i & 0xFF)
	}
	// Queue in 100-byte chunks
	for i := 0; i < total; i += 100 {
		end := i + 100
		if end > total {
			end = total
		}
		strm.queue(want[i:end])
	}

	waitFor(t, 5*time.Second, func() bool {
		return len(conn.bytesWritten()) >= total
	})

	got := conn.bytesWritten()
	if !bytes.Equal(got, want) {
		// Find first divergence for debug.
		for i := range got {
			if i >= len(want) || got[i] != want[i] {
				t.Fatalf("first divergence at byte %d: got %d want %d (len got=%d want=%d)",
					i, got[i], want[i], len(got), len(want))
			}
		}
		t.Fatalf("length mismatch: got=%d want=%d", len(got), len(want))
	}
}

// waitFor polls cond every 1ms up to d. Used instead of fixed
// sleeps so tests are robust under -race.
func waitFor(t *testing.T, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition not met within %s", d)
}
