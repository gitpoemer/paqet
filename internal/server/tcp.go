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

	// One direction inline + one spawned. When either direction returns
	// (peer EOF, error, or ctx-cancel-driven close from the defer above),
	// the conn.Close / strm.Close from the surrounding deferred cleanup
	// also tears down the OTHER direction's CopyT, so we don't strand the
	// spawned goroutine. Saves one goroutine per accepted stream vs the
	// old 2-goroutine pattern. See OPTIMIZE_NOTES.md plan item #4.
	errCh := make(chan error, 1)
	go func() {
		errCh <- buffer.CopyT(conn, strm)
	}()
	inlineErr := buffer.CopyT(strm, conn)
	// Closing conn here would already happen via the defer at function
	// exit; closing it now unblocks the spawned CopyT immediately.
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
