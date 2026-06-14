package socks

import (
	"context"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
)

// HandleConnect runs the SOCKS5 CONNECT relay. The greeting + auth +
// request handshake has already completed by the time this is called,
// and a SUCCESS reply has been sent to conn. Our job is to open a
// tunnel stream to dest and bidi-copy between it and conn.
func (h *Handler) HandleConnect(ctx context.Context, conn net.Conn, dest AddrSpec) error {
	target := dest.String()
	flog.Infof("SOCKS5 accepted TCP connection %s -> %s", conn.RemoteAddr(), target)

	strm, err := h.client.TCP(target)
	if err != nil {
		flog.Errorf("SOCKS5 failed to establish stream for %s -> %s: %v", conn.RemoteAddr(), target, err)
		return err
	}
	defer strm.Close()
	flog.Debugf("SOCKS5 stream %d created for %s -> %s", strm.SID(), conn.RemoteAddr(), target)

	inlineErr, bgErr := buffer.RelayBidi(conn, strm)

	if h.ctx.Err() != nil {
		flog.Debugf("SOCKS5 connection %s -> %s closed due to shutdown", conn.RemoteAddr(), target)
	} else if inlineErr != nil {
		flog.Errorf("SOCKS5 stream %d failed for %s -> %s (out): %v", strm.SID(), conn.RemoteAddr(), target, inlineErr)
	} else if bgErr != nil {
		flog.Errorf("SOCKS5 stream %d failed for %s -> %s (in): %v", strm.SID(), conn.RemoteAddr(), target, bgErr)
	}

	flog.Debugf("SOCKS5 connection %s -> %s closed", conn.RemoteAddr(), target)
	return nil
}
