package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/tnet"
	"sync"
	"time"
)

// udpClient is the subset of *client.Client that the UDP relay needs.
// Factored out so tests can inject a fake without spinning up real
// KCP/smux infrastructure.
type udpClient interface {
	UDP(lAddr, tAddr string) (tnet.Strm, bool, uint64, error)
	CloseUDP(key uint64) error
}

// HandleUDPAssociate runs the SOCKS5 UDP relay for one association.
//
// SOCKS5 UDP semantics:
//   - The TCP control conn (clientCtl) stays open for the lifetime of
//     the association. When it closes, we close the UDP socket and
//     terminate any per-client goroutines.
//   - Inbound UDP datagrams from the SOCKS5 client carry a destination
//     spec wrapped in a small header (RSV+FRAG+ATYP+DST+payload).
//     We parse, look up / open the corresponding tunnel stream
//     (per (clientUDPAddr, targetAddr) pair), and write the payload
//     onto it.
//   - The reverse direction (tunnel → client) is one goroutine per
//     stream, reading from the stream and writing to the SOCKS5 client
//     via udp.WriteTo with the SOCKS5 UDP header re-prepended.
//
// We don't support FRAG != 0 — RFC 1928 allows implementations to drop
// fragments, and supporting reassembly would be substantial code with
// negligible real-world demand.
func (h *Handler) HandleUDPAssociate(ctx context.Context, udp *net.UDPConn, clientCtl net.Conn) error {
	// Track stream lifetime per (clientUDPAddr, targetAddr) so multiple
	// targets from the same client port multiplex without contention.
	// Reader goroutines for each stream share this map for cleanup.
	streams := &udpStreamSet{
		client:     h.client,
		udp:        udp,
		clientAddr: nil, // first datagram fixes this
		entries:    make(map[string]*udpStreamEntry),
	}
	defer streams.closeAll()

	// One goroutine watches the TCP control conn; when it closes, we
	// tear down the UDP side. That's how SOCKS5 signals end-of-life.
	ctlDone := make(chan struct{})
	go func() {
		defer close(ctlDone)
		_, _ = io.Copy(io.Discard, clientCtl)
	}()

	// One goroutine watches ctx for shutdown to unblock UDP reads.
	go func() {
		select {
		case <-ctx.Done():
			udp.Close()
		case <-ctlDone:
			udp.Close()
		}
	}()

	buf := make([]byte, buffer.UPool)
	for {
		n, src, err := udp.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		dg, err := ParseUDPDatagram(buf[:n])
		if err != nil {
			flog.Debugf("SOCKS5 UDP bad datagram from %s: %v", src, err)
			continue
		}

		// First datagram from any client locks the relay to that
		// client. RFC 1928 §6 leaves the spec vague on this; locking
		// matches the txthinking behavior and keeps a stranger from
		// piggybacking on a live UDP association.
		if streams.clientAddr == nil {
			streams.clientAddr = src
		} else if !udpEqual(streams.clientAddr, src) {
			flog.Debugf("SOCKS5 UDP datagram from unexpected client %s (expected %s)", src, streams.clientAddr)
			continue
		}

		target := dg.Dest.String()
		entry, isNew, err := streams.getOrCreate(src, target, dg.Dest)
		if err != nil {
			flog.Errorf("SOCKS5 UDP open stream %s -> %s: %v", src, target, err)
			continue
		}

		// Outbound: write the payload to the tunnel stream.
		_ = entry.strm.SetWriteDeadline(time.Now().Add(8 * time.Second))
		if _, err := entry.strm.Write(dg.Data); err != nil {
			flog.Debugf("SOCKS5 UDP write %s -> %s: %v", src, target, err)
			streams.closeOne(entry.key)
			continue
		}
		_ = entry.strm.SetWriteDeadline(time.Time{})

		if isNew {
			flog.Infof("SOCKS5 accepted UDP connection %s -> %s", src, target)
		}
	}
}

// udpStreamEntry pins a tunnel stream and the goroutine that reads
// from it on behalf of one (clientAddr, target) pair.
//
// clientKey is the key returned by client.UDP — it identifies the
// stream in the CLIENT-wide udpPool (shared across all
// HandleUDPAssociate invocations). We need it so closeOne can call
// client.CloseUDP and free the cached entry; without that call, the
// client-wide pool accumulates stale Closed streams forever, and
// future client.UDP lookups for the same (src, target) pair return
// the dead pointer and all I/O on it fails. That's the
// "connection-stops-working-after-a-while" symptom for
// long-lived-fixed-port UDP flows (QUIC, MTProto, etc).
type udpStreamEntry struct {
	key       string
	clientKey uint64
	strm      tnet.Strm
	src       *net.UDPAddr // SOCKS5 client UDP source
	dest      AddrSpec
}

type udpStreamSet struct {
	mu         sync.Mutex
	client     udpClient
	udp        *net.UDPConn
	clientAddr *net.UDPAddr
	entries    map[string]*udpStreamEntry
}

func (s *udpStreamSet) getOrCreate(src *net.UDPAddr, target string, dest AddrSpec) (*udpStreamEntry, bool, error) {
	key := src.String() + "|" + target

	s.mu.Lock()
	if e, ok := s.entries[key]; ok {
		s.mu.Unlock()
		return e, false, nil
	}
	s.mu.Unlock()

	strm, _, clientKey, err := s.client.UDP(src.String(), target)
	if err != nil {
		return nil, false, err
	}

	s.mu.Lock()
	if existing, found := s.entries[key]; found {
		// Lost a race; close ours, return the winner. Also free the
		// client-side pool entry we just allocated.
		s.mu.Unlock()
		strm.Close()
		_ = s.client.CloseUDP(clientKey)
		return existing, false, nil
	}
	entry := &udpStreamEntry{key: key, clientKey: clientKey, strm: strm, src: src, dest: dest}
	s.entries[key] = entry
	s.mu.Unlock()

	go s.readerLoop(entry)
	return entry, true, nil
}

func (s *udpStreamSet) readerLoop(e *udpStreamEntry) {
	defer s.closeOne(e.key)

	buf := make([]byte, buffer.UPool)
	scratch := make([]byte, 0, 64) // for the SOCKS5 UDP header
	for {
		_ = e.strm.SetReadDeadline(time.Now().Add(60 * time.Second))
		n, err := e.strm.Read(buf)
		_ = e.strm.SetReadDeadline(time.Time{})
		if err != nil {
			flog.Debugf("SOCKS5 UDP stream %d read end %s -> %s: %v", e.strm.SID(), e.src, e.dest, err)
			return
		}
		need := UDPDatagramEncodedLen(e.dest, n)
		if cap(scratch) < need {
			scratch = make([]byte, need)
		} else {
			scratch = scratch[:need]
		}
		written := EncodeUDPDatagram(scratch, e.dest, buf[:n])
		if _, err := s.udp.WriteToUDP(scratch[:written], e.src); err != nil {
			flog.Debugf("SOCKS5 UDP write to client %s: %v", e.src, err)
			return
		}
	}
}

// closeOne removes the entry from BOTH our local map AND the
// client-wide udpPool. Failing to do the latter is the bug fixed in
// alpha.30 — see udpStreamEntry.clientKey comment.
func (s *udpStreamSet) closeOne(key string) {
	s.mu.Lock()
	e, ok := s.entries[key]
	if ok {
		delete(s.entries, key)
	}
	s.mu.Unlock()
	if ok {
		_ = s.client.CloseUDP(e.clientKey)
		// CloseUDP already closes the strm via udpPool.delete; an
		// extra Close on a closed tnet.Strm is harmless (idempotent
		// smux Close), and we use it as defense if CloseUDP changes
		// to not close in the future.
		e.strm.Close()
	}
}

func (s *udpStreamSet) closeAll() {
	s.mu.Lock()
	all := make([]*udpStreamEntry, 0, len(s.entries))
	for _, e := range s.entries {
		all = append(all, e)
	}
	s.entries = nil
	s.mu.Unlock()
	for _, e := range all {
		_ = s.client.CloseUDP(e.clientKey)
		e.strm.Close()
	}
}

func udpEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}
