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
	dialer := egressDialer(10*time.Second, int(s.cfg.Transport.EgressMark))
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
