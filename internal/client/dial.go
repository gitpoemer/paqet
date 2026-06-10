package client

import (
	"errors"
	"fmt"
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"time"
)

// newStrmMaxRetries caps how many recovery passes one stream-open will attempt
// before giving up and returning an error to the caller (which can then drop
// the inbound connection cleanly).
//
// Old code (master) recursed without bound. A single broken KCP session blew
// the goroutine stack and wedged every consumer of the client; this is the
// most likely root cause of the "stops working after a while" symptom.
const newStrmMaxRetries = 4

// newConn picks the next *timedConn under c.mu (briefly), then operates on it
// without holding the client-wide lock. Ping/createConn used to run inside
// c.mu which serialized every consumer behind a single (potentially slow) DNS
// + KCP handshake.
//
// Concurrency model on tc:
//   - tc.mu.RLock() for the happy-path read of tc.conn so the load races
//     against an in-flight recovery WITHOUT a chance of observing a nil
//     pointer. RLock is contention-free against other RLock holders.
//   - tc.mu.Lock() for recovery. Released only after either (a) we've
//     installed a working fresh conn, or (b) we've decided to leave the
//     old (broken) conn in place because recovery failed.
//
// We deliberately do NOT nil out tc.conn on recovery failure. The old
// broken pointer stays in place; the next caller's Ping() will fail on
// it and re-enter recovery. v1.0.0-alpha.20-optimize did the opposite
// and that meant every subsequent caller hit a nil-pointer panic if
// createConn ever failed — see OPTIMIZE_NOTES.md review pass.
func (c *Client) newConn() (tnet.Conn, error) {
	c.mu.Lock()
	tc := c.iter.Next()
	c.mu.Unlock()

	// Happy path: read tc.conn under RLock (no contention with other
	// readers, blocks against an in-flight recovery writer).
	tc.mu.RLock()
	current := tc.conn
	tc.mu.RUnlock()
	if current != nil {
		if err := current.Ping(false); err == nil {
			return current, nil
		}
	}

	// Recovery: writer lock.
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Re-check after upgrading — another goroutine may have already healed
	// the conn while we were waiting for the write lock.
	if tc.conn != nil {
		if err := tc.conn.Ping(false); err == nil {
			return tc.conn, nil
		}
	}

	flog.Infof("connection lost, recreating...")
	fresh, err := tc.createConn()
	if err != nil {
		// Leave whatever was in tc.conn alone. If it's a closed/broken
		// conn, the next caller's Ping will fail on it and we'll retry
		// recovery. If it's nil (very first call hit an error here),
		// the next caller's Ping path skips it via the nil-check above
		// and also retries. We never write nil here, so we never poison
		// the pointer with a worse sentinel than what was there before.
		return nil, fmt.Errorf("recreate connection: %w", err)
	}

	// Swap to fresh first, then close the old one — anyone who already
	// loaded the old pointer via the RLock above gets to use it until
	// they release their last reference. Their next Ping will fail and
	// they'll re-enter recovery; the bounded retry budget in newStrm
	// keeps that from looping.
	old := tc.conn
	tc.conn = fresh
	if old != nil {
		old.Close()
	}
	return tc.conn, nil
}

// newStrm tries to open a multiplexed stream, retrying on a bounded budget.
// Each iteration sleeps progressively longer so a flapping link doesn't pin
// a CPU core.
func (c *Client) newStrm() (tnet.Strm, error) {
	var lastErr error
	for attempt := 0; attempt < newStrmMaxRetries; attempt++ {
		conn, err := c.newConn()
		if err != nil {
			lastErr = err
			flog.Debugf("newConn attempt %d/%d failed: %v", attempt+1, newStrmMaxRetries, err)
			sleepBackoff(attempt)
			continue
		}
		strm, err := conn.OpenStrm()
		if err == nil {
			return strm, nil
		}
		lastErr = err
		flog.Debugf("OpenStrm attempt %d/%d failed: %v", attempt+1, newStrmMaxRetries, err)
		sleepBackoff(attempt)
	}
	if lastErr == nil {
		lastErr = errors.New("newStrm: exhausted retries")
	}
	return nil, fmt.Errorf("newStrm gave up after %d attempts: %w", newStrmMaxRetries, lastErr)
}

// sleepBackoff: 50ms, 100ms, 200ms, 400ms — capped at the loop's retry budget.
func sleepBackoff(attempt int) {
	d := 50 * time.Millisecond
	for i := 0; i < attempt && d < 500*time.Millisecond; i++ {
		d *= 2
	}
	time.Sleep(d)
}
