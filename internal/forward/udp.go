package forward

import (
	"context"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/tnet"
	"time"
)

// serveUDP runs the receive loop on an already-bound conn. Binding and the
// ctx-driven close happen in startUDP so bind errors surface to Start.
func (f *Forward) serveUDP(ctx context.Context, conn *net.UDPConn) {
	defer conn.Close()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := f.handleUDPPacket(ctx, conn); err != nil {
			flog.Errorf("UDP packet handling failed on %s: %v", f.listenAddr, err)
		}
	}
}

func (f *Forward) handleUDPPacket(ctx context.Context, conn *net.UDPConn) error {
	buf := make([]byte, buffer.UPool)

	n, caddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}

	strm, new, k, err := f.client.UDP(caddr.String(), f.targetAddr)
	if err != nil {
		// No CloseUDP here: on the create-error path k is 0 (no pooled
		// stream), so CloseUDP(k) is a no-op that just takes a lock and
		// logs a spurious "key 0 not found". Matches upstream b80fce8.
		flog.Errorf("failed to establish UDP stream for %s -> %s: %v", caddr, f.targetAddr, err)
		return err
	}

	if _, err := strm.Write(buf[:n]); err != nil {
		flog.Errorf("failed to forward %d bytes from %s -> %s: %v", n, caddr, f.targetAddr, err)
		f.client.CloseUDP(k)
		return err
	}
	if new {
		flog.Infof("accepted UDP connection %d for %s -> %s", strm.SID(), caddr, f.targetAddr)
		go f.handleUDPStrm(ctx, k, strm, conn, caddr)
	}

	return nil
}

func (f *Forward) handleUDPStrm(ctx context.Context, k uint64, strm tnet.Strm, conn *net.UDPConn, caddr *net.UDPAddr) {
	buf := make([]byte, buffer.UPool)
	defer func() {
		flog.Debugf("UDP stream %d closed for %s -> %s", strm.SID(), caddr, f.targetAddr)
		f.client.CloseUDP(k)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// SetReadDeadline, not SetDeadline: handleUDPPacket writes to this
		// same strm concurrently, and SetDeadline would clobber that
		// writer's deadline. Matches upstream c680429.
		strm.SetReadDeadline(time.Now().Add(8 * time.Second))
		n, err := strm.Read(buf)
		strm.SetReadDeadline(time.Time{})
		if err != nil {
			flog.Errorf("UDP stream %d read failed for %s -> %s: %v", strm.SID(), caddr, f.targetAddr, err)
			return
		}
		_, err = conn.WriteToUDP(buf[:n], caddr)
		if err != nil {
			flog.Errorf("UDP stream %d write failed for %s -> %s: %v", strm.SID(), caddr, f.targetAddr, err)
			return
		}
	}
}
