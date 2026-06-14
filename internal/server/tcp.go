package server

import (
	"context"
	"io"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/protocol"
	"paqet/internal/relay"
	"paqet/internal/tnet"
	"time"

	smux "github.com/xtaci/smux"
)

func (s *Server) handleTCPProtocol(ctx context.Context, strm tnet.Strm, p *protocol.Proto) error {
	flog.Infof("accepted TCP stream %d: %s -> %s", strm.SID(), strm.RemoteAddr(), p.Addr.String())
	return s.handleTCP(ctx, strm, p.Addr.String())
}

func (s *Server) handleTCP(ctx context.Context, strm tnet.Strm, addr string) error {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		flog.Errorf("failed to establish TCP connection to %s for stream %d: %v", addr, strm.SID(), err)
		return err
	}
	// SO_KEEPALIVE on outbound dial: detect dead targets without waiting
	// for the Linux default of 2h idle. Period of 30s + 9 probes ≈ 4.5
	// min to declare dead — short enough that zombie streams don't pin
	// the smux session-wide buffer, long enough that legitimate idle
	// connections (HTTP/2 keep-alive, WebSocket between messages)
	// aren't killed. Without this, a target that goes silent (peer
	// reboot, NAT drop, BGP withdrawal) leaves the relay sitting on
	// conn.Read forever — exactly the alpha.31 UDP failure mode in TCP
	// form.
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	defer func() {
		conn.Close()
		flog.Debugf("closed TCP connection %s for stream %d", addr, strm.SID())
	}()
	flog.Debugf("TCP connection established to %s for stream %d", addr, strm.SID())

	// Choose relay implementation based on the per-session
	// SessionRelay attached via context (alpha.34 item 10 opt-in).
	// Coordinator path delegates the strm→conn direction to a
	// shared per-session goroutine; the inline conn→strm direction
	// runs in this goroutine (the same one that handleStrm already
	// uses, so no extra goroutine cost). Default falls back to
	// alpha.28 RelayBidi which spawns one BG goroutine per stream.
	sr := relayFromCtx(ctx)
	if sr != nil {
		return s.runCoordinatorRelay(sr, strm, conn, addr)
	}

	inlineErr, bgErr := buffer.RelayBidi(conn, strm)

	// Surface the most informative error: ctx-cancel takes priority,
	// then the inline direction (covers TCP-from-tunnel-to-target),
	// then the background direction.
	if ctx.Err() != nil {
		return nil
	}
	if inlineErr != nil {
		flog.Errorf("TCP stream %d to %s failed (out): %v", strm.SID(), addr, inlineErr)
		return inlineErr
	}
	if bgErr != nil {
		flog.Errorf("TCP stream %d to %s failed (in): %v", strm.SID(), addr, bgErr)
		return bgErr
	}
	return nil
}

// runCoordinatorRelay is the alpha.34 item 10 path. The strm→conn
// direction is registered with the per-session SessionRelay (no
// dedicated goroutine — coordinator + lazy worker). This goroutine
// runs the inline conn→strm direction synchronously, then
// unregisters on exit.
//
// Casting tnet.Strm to *smux.Stream is safe in production because
// our concrete Strm IS a smux Stream wrapped by kcp.Strm
// (internal/tnet/kcp/strm.go). The cast fails gracefully back to
// per-stream relay if a future Strm impl doesn't satisfy the
// coordinator's interface.
func (s *Server) runCoordinatorRelay(sr *relay.SessionRelay, strm tnet.Strm, conn net.Conn, addr string) error {
	relayStrm, ok := unwrapToCoordinatorStrm(strm)
	if !ok {
		flog.Debugf("stream %d: Strm type doesn't satisfy coordinator interface, falling back to per-stream relay", strm.SID())
		inlineErr, bgErr := buffer.RelayBidi(conn, strm)
		_, _ = inlineErr, bgErr
		return nil
	}

	sr.Register(relayStrm, conn)
	defer sr.Unregister(relayStrm.ID())

	// Inline direction: conn → strm. Runs synchronously here. When
	// conn closes (local app done), this Copy returns; we close strm
	// so the coordinator's worker can drain and exit.
	_, err := io.Copy(strm, conn)
	if err != nil && err != io.EOF {
		flog.Debugf("TCP stream %d inline (conn->strm) returned: %v", strm.SID(), err)
	}
	return nil
}

// unwrapToCoordinatorStrm extracts the underlying *smux.Stream from
// our tnet.Strm wrapper. Returns false if the cast fails (tests with
// fake Strms, future non-smux backends).
func unwrapToCoordinatorStrm(strm tnet.Strm) (relay.Strm, bool) {
	if s, ok := strm.(interface{ Unwrap() *smux.Stream }); ok {
		if u := s.Unwrap(); u != nil {
			return u, true
		}
	}
	return nil, false
}

// silence unused-import linter for smux when only the cast path is
// disabled (above). The package is used implicitly via the Unwrap
// interface satisfaction in tnet/kcp/strm.go.
var _ = smux.ErrWouldBlock
