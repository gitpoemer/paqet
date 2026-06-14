package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"sync"
	"time"
)

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
		entry, isNew, err := streams.getOrCreate(h, src, target, dg.Dest)
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
type udpStreamEntry struct {
	key  string
	strm udpStrm
	src  *net.UDPAddr // SOCKS5 client UDP source
	dest AddrSpec
}

// udpStrm is the subset of tnet.Strm that the UDP relay needs. Helps
// tests inject mocks.
type udpStrm interface {
	io.ReadWriteCloser
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SID() int
}

type udpStreamSet struct {
	mu         sync.Mutex
	udp        *net.UDPConn
	clientAddr *net.UDPAddr
	entries    map[string]*udpStreamEntry
}

func (s *udpStreamSet) getOrCreate(h *Handler, src *net.UDPAddr, target string, dest AddrSpec) (*udpStreamEntry, bool, error) {
	key := src.String() + "|" + target

	s.mu.Lock()
	if e, ok := s.entries[key]; ok {
		s.mu.Unlock()
		return e, false, nil
	}
	s.mu.Unlock()

	strmRaw, _, _, err := h.client.UDP(src.String(), target)
	if err != nil {
		return nil, false, err
	}
	strm, ok := strmRaw.(udpStrm)
	if !ok {
		strmRaw.Close()
		return nil, false, errors.New("client.UDP returned non-udpStrm")
	}

	s.mu.Lock()
	if existing, found := s.entries[key]; found {
		// Lost a race; close ours, return the winner.
		s.mu.Unlock()
		strm.Close()
		return existing, false, nil
	}
	entry := &udpStreamEntry{key: key, strm: strm, src: src, dest: dest}
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

func (s *udpStreamSet) closeOne(key string) {
	s.mu.Lock()
	e, ok := s.entries[key]
	if ok {
		delete(s.entries, key)
	}
	s.mu.Unlock()
	if ok {
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
		e.strm.Close()
	}
}

func udpEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}
