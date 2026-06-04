package socket

// tcpconn.go implements a net.PacketConn over real TCP sockets.
//
// Use case: environments where paqet's pcap-injected raw-TCP packets are
// dropped by stateful middleboxes (mobile carrier NAT/CGN, TCP PEPs) because
// the KCP-driven sequence numbers don't match the conntrack entry the
// middlebox built from the client's outbound SYN. Real kernel TCP sockets
// produce correctly-sequenced packets that pass middlebox conntrack checks.
//
// Each KCP "packet" is framed on the TCP byte stream with a 2-byte big-endian
// length prefix followed by the payload. The KCP layer above is unaware of
// the framing — it sees a normal net.PacketConn with per-packet semantics.
//
// On the server, each accepted TCP connection is demuxed into a synthetic
// *net.UDPAddr (built from the client's TCP source IP/port) so the KCP layer
// can route packets to the right session. On the client, a single TCP
// connection backs the single PacketConn.
//
// No raw sockets, no pcap, no special capabilities. Runs as an unprivileged
// user provided the listen port is ≥ 1024 (or CAP_NET_BIND_SERVICE is granted).

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"paqet/internal/conf"
)

const (
	tcpMaxPacketLen = 65535 // 2-byte length prefix → max 65535 bytes per KCP packet
	tcpReadQueueCap = 1024  // buffered packets between reader goroutines and KCP
)

// TCPConn implements net.PacketConn backed by real TCP sockets.
type TCPConn struct {
	isServer bool

	// Server mode
	listener net.Listener
	clients  sync.Map // remote-addr-string → *tcpStream

	// Client mode
	clientStream *tcpStream
	remoteAddr   net.Addr // synthetic *net.UDPAddr representing the server

	// Both modes
	readQueue     chan readPacket
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
}

type tcpStream struct {
	conn    net.Conn
	remote  net.Addr // synthetic *net.UDPAddr for KCP demux
	parent  *TCPConn
	writeMu sync.Mutex
}

type readPacket struct {
	data []byte
	addr net.Addr
}

// NewTCPServer creates a TCP-carrier PacketConn in server mode, listening
// on listenAddr. Each accepted TCP connection is demuxed via a synthetic
// *net.UDPAddr derived from the client's TCP remote address.
func NewTCPServer(ctx context.Context, listenAddr *net.TCPAddr) (*TCPConn, error) {
	l, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("tcp-carrier listen on %s: %w", listenAddr, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	tc := &TCPConn{
		isServer:  true,
		listener:  l,
		readQueue: make(chan readPacket, tcpReadQueueCap),
		ctx:       ctx,
		cancel:    cancel,
	}
	go tc.acceptLoop()
	return tc, nil
}

// NewTCPClient creates a TCP-carrier PacketConn in client mode, dialing the
// server at serverAddr.
func NewTCPClient(ctx context.Context, serverAddr *net.TCPAddr) (*TCPConn, error) {
	c, err := net.DialTCP("tcp", nil, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("tcp-carrier dial %s: %w", serverAddr, err)
	}
	configureTCPConn(c)
	ctx, cancel := context.WithCancel(ctx)
	// KCP-go uses *net.UDPAddr internally; expose the server as a synthetic
	// UDPAddr so KCP's address comparisons work.
	synth := &net.UDPAddr{IP: serverAddr.IP, Port: serverAddr.Port, Zone: serverAddr.Zone}
	tc := &TCPConn{
		isServer:   false,
		remoteAddr: synth,
		readQueue:  make(chan readPacket, tcpReadQueueCap),
		ctx:        ctx,
		cancel:     cancel,
	}
	tc.clientStream = &tcpStream{conn: c, remote: synth, parent: tc}
	go tc.readLoop(tc.clientStream)
	return tc, nil
}

func configureTCPConn(c *net.TCPConn) {
	_ = c.SetNoDelay(true)
	_ = c.SetKeepAlive(true)
	_ = c.SetKeepAlivePeriod(30 * time.Second)
}

func (tc *TCPConn) acceptLoop() {
	for {
		c, err := tc.listener.Accept()
		if err != nil {
			if tc.closed.Load() {
				return
			}
			// Transient accept errors: wait briefly and retry.
			select {
			case <-tc.ctx.Done():
				return
			case <-time.After(100 * time.Millisecond):
			}
			continue
		}
		if tcpC, ok := c.(*net.TCPConn); ok {
			configureTCPConn(tcpC)
		}
		raddr, ok := c.RemoteAddr().(*net.TCPAddr)
		if !ok {
			c.Close()
			continue
		}
		synth := &net.UDPAddr{IP: raddr.IP, Port: raddr.Port, Zone: raddr.Zone}
		stream := &tcpStream{conn: c, remote: synth, parent: tc}
		tc.clients.Store(synth.String(), stream)
		go tc.readLoop(stream)
	}
}

func (tc *TCPConn) readLoop(stream *tcpStream) {
	defer func() {
		stream.conn.Close()
		if tc.isServer {
			tc.clients.Delete(stream.remote.String())
		}
	}()
	var lenBuf [2]byte
	for {
		// Read length prefix.
		if _, err := io.ReadFull(stream.conn, lenBuf[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint16(lenBuf[:])
		if n == 0 {
			// Zero-length frames are treated as keepalive markers; ignored.
			continue
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(stream.conn, buf); err != nil {
			return
		}
		select {
		case tc.readQueue <- readPacket{data: buf, addr: stream.remote}:
		case <-tc.ctx.Done():
			return
		}
	}
}

// ReadFrom satisfies net.PacketConn.
func (tc *TCPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var deadlineCh <-chan time.Time
	if d, ok := tc.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadlineCh = timer.C
	}
	select {
	case <-tc.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-deadlineCh:
		return 0, nil, os.ErrDeadlineExceeded
	case pkt := <-tc.readQueue:
		return copy(p, pkt.data), pkt.addr, nil
	}
}

// WriteTo satisfies net.PacketConn.
//
// Framing is one length-prefixed frame per call, written as a single kernel
// write (via net.Buffers / writev) so length + body are atomically delivered
// even under concurrent pressure or partial-write scenarios. A previous
// implementation used two consecutive Write() calls and was vulnerable to
// permanent stream desync if the second call failed after the first
// succeeded — receiver would parse the partial body as a length prefix.
func (tc *TCPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if tc.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > tcpMaxPacketLen {
		return 0, fmt.Errorf("tcp-carrier: packet %d > max %d", len(p), tcpMaxPacketLen)
	}
	if d, ok := tc.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		if time.Now().After(d) {
			return 0, os.ErrDeadlineExceeded
		}
	}

	var stream *tcpStream
	if tc.isServer {
		key := addr.String()
		v, ok := tc.clients.Load(key)
		if !ok {
			return 0, fmt.Errorf("tcp-carrier: no TCP stream for %s", key)
		}
		stream = v.(*tcpStream)
	} else {
		stream = tc.clientStream
	}

	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(p)))

	stream.writeMu.Lock()
	defer stream.writeMu.Unlock()

	// Sync the underlying TCP conn's write deadline to our stored value.
	// When the caller clears the deadline by storing time.Time{}, we must
	// actively clear it on the conn too (passing zero time to
	// SetWriteDeadline disables the deadline); otherwise a stale past
	// deadline from an earlier call would fail every subsequent write
	// with ErrDeadlineExceeded.
	d, _ := tc.writeDeadline.Load().(time.Time)
	_ = stream.conn.SetWriteDeadline(d)

	// writev one frame as a single atomic kernel call.
	buffers := net.Buffers{lenBuf[:], p}
	if _, err := buffers.WriteTo(stream.conn); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close satisfies net.PacketConn.
func (tc *TCPConn) Close() error {
	if !tc.closed.CompareAndSwap(false, true) {
		return nil
	}
	tc.cancel()
	if tc.listener != nil {
		_ = tc.listener.Close()
	}
	if tc.clientStream != nil {
		_ = tc.clientStream.conn.Close()
	}
	tc.clients.Range(func(_, v any) bool {
		if s, ok := v.(*tcpStream); ok {
			_ = s.conn.Close()
		}
		return true
	})
	return nil
}

// LocalAddr satisfies net.PacketConn.
func (tc *TCPConn) LocalAddr() net.Addr {
	if tc.listener != nil {
		return tc.listener.Addr()
	}
	if tc.clientStream != nil {
		return tc.clientStream.conn.LocalAddr()
	}
	return nil
}

// SetDeadline satisfies net.PacketConn.
func (tc *TCPConn) SetDeadline(t time.Time) error {
	tc.readDeadline.Store(t)
	tc.writeDeadline.Store(t)
	return nil
}

// SetReadDeadline satisfies net.PacketConn.
func (tc *TCPConn) SetReadDeadline(t time.Time) error {
	tc.readDeadline.Store(t)
	return nil
}

// SetWriteDeadline satisfies net.PacketConn.
func (tc *TCPConn) SetWriteDeadline(t time.Time) error {
	tc.writeDeadline.Store(t)
	return nil
}

// SetDSCP is a no-op for TCP carrier (kernel handles QoS via socket options).
func (tc *TCPConn) SetDSCP(int) error { return nil }

// SetClientTCPF is a no-op for TCP carrier — TCP flags are managed by the
// kernel, not by the application. Kept on the type so the server's
// per-client-flag dispatch code can call it uniformly across carrier types.
func (tc *TCPConn) SetClientTCPF(net.Addr, []conf.TCPF) {}

// Compile-time check that TCPConn satisfies net.PacketConn.
var _ net.PacketConn = (*TCPConn)(nil)
