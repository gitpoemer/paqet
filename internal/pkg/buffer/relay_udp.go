package buffer

import (
	"errors"
	"io"
	"net"
	"time"
)

// UDPEndpoint is the subset of net.Conn / smux.Stream that the UDP
// relay needs. Both net.UDPConn and *smux.Stream satisfy it.
type UDPEndpoint interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
}

// DefaultUDPIdleTimeout is the default both-direction-quiet timeout
// for UDP relays.
//
// 30s is below typical consumer-NAT UDP timeout (30-60s), which is
// the de-facto ceiling for any UDP service that wants to stay alive
// across home routers. Every protocol designed to traverse NAT
// pings well under that ceiling:
//   - WireGuard keepalive: 25s
//   - QUIC PING / ack-eliciting: 15-20s in idle
//   - WebRTC STUN keepalive: 5-15s
//   - MTProto (Telegram) on active sessions: well under 30s
//
// So 30s never kills an alive session, while being short enough
// that single-shot UDP (DNS, NTP, traceroute, "1 query then dead")
// frees its per-stream smux buffer fast. At 142 streams/sec arrival
// rate this caps zombie buffer pressure at ~270 MB (half of 60s).
//
// Override via conf.Transport.UDPIdleTimeout when the deployment is
// dominated by either short queries (lower) or sticky sessions
// (higher).
const DefaultUDPIdleTimeout = 30 * time.Second

// RelayUDPBidi runs a bidirectional UDP relay between strm and conn.
// Returns when either side errors OR neither side has read any byte
// for idleTimeout. Closes BOTH endpoints on return so the partner
// goroutine unblocks immediately, matching the RelayBidi pattern
// from alpha.28.
//
// Why the UDP version exists separately from RelayBidi:
//   - UDP has no FIN/EOF. A relay where both apps stop sending
//     would sit forever in two CopyBuffer loops without a deadline.
//     That's the alpha.30→alpha.31 root cause: 486 server goroutines
//     stuck this way for 27-113 minutes each, eventually filling
//     smux's session-wide receive buffer and stalling NEW streams.
//   - TCP relays don't need this — TCP delivers FIN when a peer
//     half-closes, so a stuck Read returns naturally. RelayBidi
//     plus TCP keepalive is sufficient for TCP.
//
// idleTimeout is the per-direction Read deadline, refreshed before
// each Read. A relay where one direction is constantly active stays
// alive indefinitely — the timeout only fires when BOTH directions
// have been quiet for the full window.
func RelayUDPBidi(strm, conn UDPEndpoint, idleTimeout time.Duration) (inlineErr, bgErr error) {
	errCh := make(chan error, 1)
	go func() {
		err := copyUWithIdle(conn, strm, idleTimeout)
		strm.Close()
		conn.Close()
		errCh <- err
	}()
	inlineErr = copyUWithIdle(strm, conn, idleTimeout)
	conn.Close()
	strm.Close()
	bgErr = <-errCh
	return
}

// copyUWithIdle is a custom copy loop that sets a Read deadline
// before each Read, so a quiet endpoint times out instead of
// blocking forever. io.CopyBuffer doesn't support this because it
// has no hook between Read and Write to refresh the deadline.
//
// On idle timeout, returns nil (clean close, not an error). Any
// other Read error returns as-is.
func copyUWithIdle(dst io.Writer, src UDPEndpoint, idleTimeout time.Duration) error {
	bufAny := udpBufPool.Get()
	var buf []byte
	if bufAny == nil || len(bufAny.([]byte)) != UPool {
		buf = make([]byte, UPool)
	} else {
		buf = bufAny.([]byte)
	}
	defer udpBufPool.Put(buf)

	for {
		if err := src.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
			return err
		}
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return werr
			}
		}
		if err != nil {
			if err == io.EOF {
				// Peer closed cleanly (typically by our partner
				// direction closing it to unblock us). Clean close.
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				// Idle close; not an error to surface.
				return nil
			}
			return err
		}
	}
}
