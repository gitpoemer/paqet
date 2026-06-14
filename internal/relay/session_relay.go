// Package relay implements the per-session coordinator from
// alpha.34 item 10: replace per-stream BG goroutines with a shared
// coordinator that fans out readability events across all streams
// in one smux session.
//
// Architecture:
//
//	┌─────────────┐         ┌────────────────────┐
//	│ smux Session│         │ SessionRelay       │
//	│  stream A ──┼─events──▶  ┌───────────────┐ │
//	│  stream B ──┼─events──▶  │   coordinator  │ │
//	│  stream C ──┼─events──▶  │  reflect.Select│ │
//	│      ...    │            └───┬───────────┘ │
//	└─────────────┘                │             │
//	                              │spawn        │
//	                              ▼             │
//	                       ┌────────────┐      │
//	                       │ per-stream │      │
//	                       │  worker    │      │
//	                       │ TryRead +  │      │
//	                       │  conn.Write│      │
//	                       └────────────┘      │
//	                                            │
//	                       (worker exits when   │
//	                        TryRead returns     │
//	                        ErrWouldBlock)      │
//
// Tradeoffs vs alpha.28 RelayBidi:
//
//   - Idle streams cost 0 goroutines (they sit passively in the
//     coordinator's select set). For paqet's traffic mix (lots of
//     short HTTP, many idle keep-alives), this is a real memory win.
//
//   - Actively transferring streams still cost 1 worker goroutine
//     each — the worker only exits when the stream's smux buffer
//     drains to empty. Heavy uploads keep their worker alive
//     continuously; goroutine count for them is unchanged from
//     alpha.28.
//
//   - Wakeup latency is slightly higher: each event goes through
//     coordinator → worker spawn → first TryRead, vs alpha.28's
//     direct blocked Read returning. Adds a few microseconds.
//
//   - Reflect.Select cost is O(N) in stream count. At MaxStreams-
//     PerSession=4096 this is ~40 microseconds per dispatch on
//     commodity x86. Acceptable for sub-kHz event rate per session.
//
//   - HEAD-OF-LINE caveat: when a worker is mid-Write to a slow
//     conn, the worker holds CPU on that one stream. Other streams
//     in the same session still get coordinated (they get their
//     own workers). No HOL blocking at the coordinator level.
//
// Opt-in. Configure via conf.Transport.SessionRelay = "coordinator"
// (default "perstream" preserves alpha.28 behavior). See
// ITEM_10_SCOPE.md for the architectural decision history.
package relay

import (
	"io"
	"net"
	"reflect"
	"sync"
	"sync/atomic"
	"time"
)

// Strm is the subset of *smux.Stream that the relay needs. Lets
// tests inject mocks without spinning up real smux infrastructure.
type Strm interface {
	io.Reader
	io.Writer
	io.Closer
	TryRead(b []byte) (int, error)
	ReadEvents() <-chan struct{}
	GetDieCh() <-chan struct{}
	ID() uint32
}

// SessionRelay coordinates the strm→conn direction (BG of the
// alpha.28 bidi pair) for many streams sharing one session.
type SessionRelay struct {
	mu       sync.Mutex
	streams  map[uint32]*relayEntry
	registry chan registerOp
	done     chan struct{}
	stopped  atomic.Bool

	// bufPool reuses strm-side scratch slices across workers.
	bufPool sync.Pool
}

type registerOp struct {
	add    bool
	id     uint32
	strm   Strm
	conn   net.Conn
	doneCh chan struct{} // closed when register/unregister applied
}

type relayEntry struct {
	id            uint32
	strm          Strm
	conn          net.Conn
	workerActive  atomic.Bool
	stopped       atomic.Bool
	stoppedNotify chan struct{}
}

// NewSessionRelay creates a coordinator. Call Start to spawn the
// background goroutine; call Stop on session teardown.
func NewSessionRelay() *SessionRelay {
	return &SessionRelay{
		streams:  make(map[uint32]*relayEntry),
		registry: make(chan registerOp, 64),
		done:     make(chan struct{}),
	}
}

// Start launches the coordinator goroutine. Idempotent if called
// after Stop (returns without spawning).
func (r *SessionRelay) Start() {
	if r.stopped.Load() {
		return
	}
	go r.run()
}

// Stop halts the coordinator and closes any in-flight workers. Safe
// to call concurrently with Register / Unregister.
func (r *SessionRelay) Stop() {
	if !r.stopped.CompareAndSwap(false, true) {
		return
	}
	close(r.done)
}

// Register adds (strm, conn) to the coordinator's watch set. The
// strm→conn direction is now driven by the coordinator; the caller
// retains responsibility for the conn→strm direction (which still
// runs as the caller's own goroutine via the standard relay).
//
// Blocks briefly until the registration is applied.
func (r *SessionRelay) Register(strm Strm, conn net.Conn) {
	if r.stopped.Load() {
		return
	}
	op := registerOp{
		add: true, id: strm.ID(), strm: strm, conn: conn,
		doneCh: make(chan struct{}),
	}
	select {
	case r.registry <- op:
		<-op.doneCh
	case <-r.done:
	}
}

// Unregister removes a stream from the coordinator. Safe to call
// after the stream has closed (no-op). Blocks until applied so the
// caller can be sure no further conn writes will happen via the
// coordinator path.
func (r *SessionRelay) Unregister(strmID uint32) {
	if r.stopped.Load() {
		return
	}
	op := registerOp{
		add: false, id: strmID, doneCh: make(chan struct{}),
	}
	select {
	case r.registry <- op:
		<-op.doneCh
	case <-r.done:
	}
}

// run is the coordinator's goroutine body.
func (r *SessionRelay) run() {
	for {
		entries, sel := r.snapshotSelect()
		chosen, recv, _ := reflect.Select(sel)
		switch chosen {
		case 0:
			// r.done — shut down
			r.closeAllWorkers()
			return
		case 1:
			// r.registry — apply THIS op (already consumed from the
			// channel by reflect.Select), then drain any others.
			op := recv.Interface().(registerOp)
			r.applyOp(op)
			r.applyPendingOps()
		default:
			// One of the streams fired a ReadEvent or died. The
			// case index N≥2 corresponds to entries[(N-2)/2]:
			// even N-2 = ReadEvents, odd N-2 = die.
			idx := chosen - 2
			entry := entries[idx/2]
			if idx%2 == 0 {
				// readability event
				r.dispatch(entry)
			} else {
				// stream died — unregister and exit any worker
				r.removeEntry(entry.id)
			}
		}
	}
}

// snapshotSelect builds the reflect.SelectCase slice for the current
// stream set. Cases:
//
//	[0]   r.done
//	[1]   r.registry
//	[2N]  entries[N].strm.ReadEvents
//	[2N+1] entries[N].strm.GetDieCh
//
// Order in the entries slice is stable for the duration of one
// select call but may change between calls (we re-snapshot whenever
// the set changes).
func (r *SessionRelay) snapshotSelect() ([]*relayEntry, []reflect.SelectCase) {
	r.mu.Lock()
	entries := make([]*relayEntry, 0, len(r.streams))
	for _, e := range r.streams {
		entries = append(entries, e)
	}
	r.mu.Unlock()

	cases := make([]reflect.SelectCase, 2+2*len(entries))
	cases[0] = reflect.SelectCase{
		Dir: reflect.SelectRecv, Chan: reflect.ValueOf(r.done),
	}
	cases[1] = reflect.SelectCase{
		Dir: reflect.SelectRecv, Chan: reflect.ValueOf(r.registry),
	}
	for i, e := range entries {
		cases[2+i*2] = reflect.SelectCase{
			Dir: reflect.SelectRecv, Chan: reflect.ValueOf(e.strm.ReadEvents()),
		}
		cases[2+i*2+1] = reflect.SelectCase{
			Dir: reflect.SelectRecv, Chan: reflect.ValueOf(e.strm.GetDieCh()),
		}
	}
	return entries, cases
}

// applyPendingOps drains the registry channel and applies all
// pending registrations / unregistrations. Called by run() after
// reflect.Select fires on r.registry.
func (r *SessionRelay) applyPendingOps() {
	for {
		select {
		case op := <-r.registry:
			r.applyOp(op)
		default:
			return
		}
	}
}

func (r *SessionRelay) applyOp(op registerOp) {
	r.mu.Lock()
	if op.add {
		r.streams[op.id] = &relayEntry{
			id: op.id, strm: op.strm, conn: op.conn,
			stoppedNotify: make(chan struct{}),
		}
	} else if e, ok := r.streams[op.id]; ok {
		e.stopped.Store(true)
		close(e.stoppedNotify)
		delete(r.streams, op.id)
	}
	r.mu.Unlock()
	close(op.doneCh)
}

func (r *SessionRelay) removeEntry(id uint32) {
	r.mu.Lock()
	e, ok := r.streams[id]
	if ok {
		e.stopped.Store(true)
		close(e.stoppedNotify)
		delete(r.streams, id)
	}
	r.mu.Unlock()
}

// dispatch spawns a worker goroutine for the entry if one isn't
// already active. The worker drains the stream's buffer and writes
// it to conn until TryRead reports ErrWouldBlock; then exits.
// Subsequent ReadEvents trigger a fresh dispatch — Go scheduler
// keeps the goroutine cycle cheap.
func (r *SessionRelay) dispatch(entry *relayEntry) {
	if !entry.workerActive.CompareAndSwap(false, true) {
		// Worker already running for this stream; the next iteration
		// inside the worker will catch the new data.
		return
	}
	go r.worker(entry)
}

func (r *SessionRelay) worker(entry *relayEntry) {
	defer entry.workerActive.Store(false)

	bufAny := r.bufPool.Get()
	var buf []byte
	if bufAny == nil {
		buf = make([]byte, 32*1024)
	} else {
		buf = bufAny.([]byte)
	}
	defer r.bufPool.Put(buf)

	for {
		if entry.stopped.Load() {
			return
		}
		n, err := entry.strm.TryRead(buf)
		if n > 0 {
			if _, werr := entry.conn.Write(buf[:n]); werr != nil {
				// Write failed — propagate by closing the stream;
				// the conn→strm direction (managed by caller) will
				// also unwind.
				_ = entry.strm.Close()
				_ = entry.conn.Close()
				return
			}
		}
		if err != nil {
			if err == ErrWouldBlock {
				return // re-armed via next ReadEvent
			}
			// EOF or actual error: tear down and unregister.
			_ = entry.conn.Close()
			return
		}
	}
}

func (r *SessionRelay) closeAllWorkers() {
	r.mu.Lock()
	for _, e := range r.streams {
		e.stopped.Store(true)
		select {
		case <-e.stoppedNotify:
		default:
			close(e.stoppedNotify)
		}
	}
	r.streams = nil
	r.mu.Unlock()
}

// ErrWouldBlock is the sentinel TryRead returns when no data is
// buffered and the stream is still open. Mirrors smux.ErrWouldBlock
// so callers don't have to import smux just for the sentinel.
//
// Set at package init from third_party/smux's exported error.
var ErrWouldBlock error

// retryAfter is exposed for tests that want to assert backoff
// behavior without timing flakiness.
var retryAfter = 100 * time.Microsecond
