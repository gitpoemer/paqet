package server

import (
	"context"
	"net"
	"time"

	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
)

func (s *Server) handleUDPProtocol(ctx context.Context, strm tnet.Strm, p *protocol.Proto) error {
	flog.Infof("accepted UDP stream %d: %s -> %s", strm.SID(), strm.RemoteAddr(), p.Addr.String())
	return s.handleUDP(ctx, strm, p.Addr.String())
}

func (s *Server) handleUDP(ctx context.Context, strm tnet.Strm, addr string) error {
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := dialer.DialContext(ctx, "udp", addr)
	if err != nil {
		flog.Errorf("failed to establish UDP connection to %s for stream %d: %v", addr, strm.SID(), err)
		return err
	}
	defer func() {
		conn.Close()
		flog.Debugf("closed UDP connection %s for stream %d", addr, strm.SID())
	}()
	flog.Debugf("UDP connection established to %s for stream %d", addr, strm.SID())

	// UDP has no FIN/EOF, so the relay MUST have an idle timeout —
	// otherwise a single DNS query (one round trip, then silence
	// forever from both sides) pins 2 goroutines and the smux
	// per-stream receive buffer until the process restarts.
	// 486 such zombies were observed in alpha.30 production after
	// ~113 minutes uptime; cumulative buffer pressure eventually
	// stalled smux entirely and blocked new stream opens at the
	// client. See OPTIMIZE_NOTES.md (alpha.31 root-cause).
	idleTimeout := buffer.DefaultUDPIdleTimeout
	if ms := s.cfg.Transport.UDPIdleTimeoutMS; ms > 0 {
		idleTimeout = time.Duration(ms) * time.Millisecond
	}
	inlineErr, bgErr := buffer.RelayUDPBidi(strm, conn, idleTimeout)

	if ctx.Err() != nil {
		return nil
	}
	if inlineErr != nil {
		flog.Errorf("UDP stream %d to %s failed (out): %v", strm.SID(), addr, inlineErr)
		return inlineErr
	}
	if bgErr != nil {
		flog.Errorf("UDP stream %d to %s failed (in): %v", strm.SID(), addr, bgErr)
		return bgErr
	}
	return nil
}
