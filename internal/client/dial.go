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
func (c *Client) newConn() (tnet.Conn, error) {
	c.mu.Lock()
	tc := c.iter.Next()
	c.mu.Unlock()

	if err := tc.conn.Ping(false); err == nil {
		return tc.conn, nil
	}

	// Recover under tc's own mutex so other Conn-holders aren't blocked.
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Re-check after acquiring — another goroutine may have already healed it.
	if err := tc.conn.Ping(false); err == nil {
		return tc.conn, nil
	}

	flog.Infof("connection lost, recreating...")
	if tc.conn != nil {
		tc.conn.Close()
		tc.conn = nil
	}
	fresh, err := tc.createConn()
	if err != nil {
		return nil, fmt.Errorf("recreate connection: %w", err)
	}
	tc.conn = fresh
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
