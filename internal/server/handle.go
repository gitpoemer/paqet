package server

import (
	"context"
	"fmt"
	"sync/atomic"

	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/relay"
	"paqet/internal/tnet"
)

// relayCtxKey is the context.Value key for the per-session
// SessionRelay (alpha.34 item 10 coordinator mode). When
// RelayMode=="coordinator", handleConn attaches one SessionRelay
// per session and handleTCP uses it instead of spawning a per-stream
// BG goroutine.
type relayCtxKey struct{}

func relayFromCtx(ctx context.Context) *relay.SessionRelay {
	if v, ok := ctx.Value(relayCtxKey{}).(*relay.SessionRelay); ok {
		return v
	}
	return nil
}

// MaxStreamsPerSession caps the number of concurrent server-side streams
// per smux session. Defense-in-depth against one misbehaving client (or
// an abuser) opening unbounded streams: each stream pins memory for the
// relay goroutines + outbound TCP/UDP socket + smux per-stream receive
// buffer. Without a cap, a single bad session could exhaust server FDs
// and goroutine memory.
//
// 4096 is well above any realistic browser session (50-500 active
// streams) plus headroom for parallel apps. A session that hits this
// is either malfunctioning or hostile; we just stop accepting new
// streams until in-flight ones drain.
const MaxStreamsPerSession = 4096

func (s *Server) handleConn(ctx context.Context, conn tnet.Conn) {
	var active atomic.Int32

	// Optionally attach a per-session SessionRelay (alpha.34 item 10).
	// Configured via transport.relaymode = "coordinator". Per-stream
	// goroutines are replaced with a shared coordinator + lazy
	// workers; idle streams cost 0 goroutines. Default mode is
	// "perstream" which preserves alpha.28 RelayBidi semantics.
	if s.cfg.Transport.RelayMode == "coordinator" {
		sr := relay.NewSessionRelay()
		sr.Start()
		defer sr.Stop()
		ctx = context.WithValue(ctx, relayCtxKey{}, sr)
	}

	for {
		select {
		case <-ctx.Done():
			flog.Debugf("stopping smux session for %s due to context cancellation", conn.RemoteAddr())
			return
		default:
		}
		strm, err := conn.AcceptStrm()
		if err != nil {
			flog.Errorf("failed to accept stream on %s: %v", conn.RemoteAddr(), err)
			return
		}
		// Per-session stream cap: if at the limit, drop the new stream
		// immediately. The cap protects against one bad session
		// monopolizing server resources; legitimate clients never reach
		// it. We log once per breach so it's visible but not noisy.
		if n := active.Add(1); n > MaxStreamsPerSession {
			active.Add(-1)
			strm.Close()
			flog.Errorf("session %s hit MaxStreamsPerSession=%d, rejecting stream %d",
				conn.RemoteAddr(), MaxStreamsPerSession, strm.SID())
			continue
		}
		s.wg.Go(func() {
			defer func() {
				active.Add(-1)
				strm.Close()
			}()
			if err := s.handleStrm(ctx, strm); err != nil {
				flog.Errorf("stream %d from %s closed with error: %v", strm.SID(), strm.RemoteAddr(), err)
			} else {
				flog.Debugf("stream %d from %s closed", strm.SID(), strm.RemoteAddr())
			}
		})
	}
}

func (s *Server) handleStrm(ctx context.Context, strm tnet.Strm) error {
	var p protocol.Proto
	err := p.Read(strm)
	if err != nil {
		flog.Errorf("failed to read protocol message from stream %d: %v", strm.SID(), err)
		return err
	}

	switch p.Type {
	case protocol.PPING:
		return s.handlePing(strm)
	case protocol.PTCPF:
		if len(p.TCPF) != 0 {
			s.pConn.SetClientTCPF(strm.RemoteAddr(), p.TCPF)
		}
		return nil
	case protocol.PTCP:
		return s.handleTCPProtocol(ctx, strm, &p)
	case protocol.PUDP:
		return s.handleUDPProtocol(ctx, strm, &p)
	default:
		flog.Errorf("unknown protocol type %d on stream %d", p.Type, strm.SID())
		return fmt.Errorf("unknown protocol type: %d", p.Type)
	}
}
