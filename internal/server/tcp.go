package server

import (
	"context"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"time"
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
	defer func() {
		conn.Close()
		flog.Debugf("closed TCP connection %s for stream %d", addr, strm.SID())
	}()
	flog.Debugf("TCP connection established to %s for stream %d", addr, strm.SID())

	// Bidi copy. When EITHER direction finishes, close the OTHER
	// side's source so the still-blocked Read unblocks immediately.
	//
	// The previous version only closed conn after the inline direction
	// returned — if the BG direction (target → tunnel) returned first
	// (target server EOF'd faster than the tunnel-side data flow),
	// inline's strm.Read sat blocked until the upstream peer eventually
	// closed the stream, leaking goroutines and smux stream-buffer
	// memory per stuck stream. See OPTIMIZE_NOTES.md (alpha.27 fix).
	//
	// Both Close calls are idempotent — handleConn's outer defer also
	// calls strm.Close, and the function-exit defer also closes conn.
	errCh := make(chan error, 1)
	go func() {
		err := buffer.CopyT(conn, strm)
		strm.Close()
		errCh <- err
	}()
	inlineErr := buffer.CopyT(strm, conn)
	_ = conn.Close()
	bgErr := <-errCh

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
