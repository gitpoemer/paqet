package socket

// cycleconn.go — handshake_cycle transport mode.
//
// Each KCP packet on the wire rides inside a fresh fake-TCP handshake cycle:
//
//   client                                                       server
//     |                                                             |
//     |  [S]   seq=X                                                |
//     | ──────────────────────────────────────────────────────────► | (carrier: new conntrack NEW→SYN_SENT)
//     |                                                             |
//     |  [SA]  seq=Y, ack=X+1                                       |
//     | ◄────────────────────────────────────────────────────────── | (carrier: SYN_RECV)
//     |                                                             |
//     |  [PA]  seq=X+1, ack=Y+1, payload=<KCP packet>               |
//     | ──────────────────────────────────────────────────────────► | (carrier: ESTABLISHED + data flow)
//     |                                                             |
//     |  [PA]  seq=Y+1, ack=X+1+N, payload=<server's queued data>   |
//     |        (or [A] with no payload if nothing to send)          |
//     | ◄────────────────────────────────────────────────────────── |
//     |                                                             |
//   (carrier conntrack times out the ESTABLISHED entry on idle;     )
//   (we don't bother with explicit FIN — saves wire packets and     )
//   (matches how some real apps abandon idle conns                  )
//
// Goal: make the wire pattern look like a stream of short legitimate-looking
// TCP connections rather than one long-lived weird one, defeating carrier
// DPI / TCP optimizers that engage on suspicious persistent flows.
//
// Source ports on the client side rotate from a 15k-port pool per packet so
// the carrier sees each cycle as a distinct connection. Server is identified
// by a fixed listen port (the configured cfg.Listen / cfg.Server port).
//
// KCP server demux: synthetic *net.UDPAddr keyed only by client_ip (port=0)
// so KCP sees one session per source IP regardless of the rotating ports.
// Limitation: multiple paqet clients sharing one source IP (uncommon) would
// collapse into one KCP session.

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mrand "math/rand/v2"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"paqet/internal/conf"
	"paqet/internal/flog"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

const (
	cyclePoolBase  uint16 = 50000
	cyclePoolSize  uint16 = 15000 // ports 50000..64999
	cycleQueueCap         = 2048
	cycleTimeout          = 5 * time.Second
	cycleMaxPacket        = 65535

	// Mode B (handshake_loop) — how long a single long-lived flow stays
	// active before rolling to a fresh source port (and new handshake).
	// The roll exists to defeat middlebox "long-lived non-standard
	// connection" detectors that engage on flows >N seconds old.
	loopRollInterval = 8 * time.Second
)

// cycleState marks how far the per-cycle TCP-mimic handshake has progressed.
type cycleState uint8

const (
	cycleInit          cycleState = iota
	cycleSynSent                  // client sent S, waiting for SA
	cycleSynReceived              // server received S, sent SA
	cycleEstablished              // handshake complete
	cycleDataDelivered            // payload received
	cycleClosed
)

// cycle holds per-handshake state on either side.
//
// All four addr fields are "local perspective" — local = us, remote = peer.
// The cycle's lookup key in the map is derived role-dependently:
//   client side: localPort (rotating per-packet, unique)
//   server side: "<remoteIP>:<remotePort>" (unique inbound 5-tuple from the
//                  client; our local side is the same listen port for all)
type cycle struct {
	localIP    net.IP
	localPort  uint16
	remoteIP   net.IP
	remotePort uint16

	mapKey string // pre-computed key for cycles map lookup

	ourSeq   uint32 // next seq we'll use when sending
	theirSeq uint32 // last seq we saw from peer

	state cycleState

	// Payload queued for sending. On client side this is the KCP packet
	// staged for the [PA] step. On server side this is the KCP packet that
	// the server's KCP layer wants to send back on this cycle's [PA] ACK.
	pending []byte

	expires time.Time
}

func (c *cycle) key() string { return c.mapKey }

func cycleKey(ip net.IP, port uint16) string {
	return fmt.Sprintf("%s:%d", ip.String(), port)
}

// CycleConn implements net.PacketConn for both the handshake_cycle and
// handshake_loop transport modes. The two modes share the same wire-level
// state machine and packet crafting; they differ only in cycle lifecycle:
//
//   handshake_cycle — one cycle per KCP packet, ephemeral. Each client
//                     WriteTo allocates a new source port + new cycle.
//                     Designed to look like many short legit-looking TCP
//                     connections (per-packet rotation).
//
//   handshake_loop  — one persistent cycle per WriteTo flow, periodically
//                     rolled to a new source port every loopRollInterval
//                     (8s). The roll is a graceful close (FIN/ACK) + new
//                     SYN sequence so the carrier sees the connection
//                     close cleanly and a fresh one open. Designed for
//                     environments where per-packet rotation is too
//                     suspicious (SYN-flood-detector territory).
type CycleConn struct {
	cfg      *conf.Network
	isServer bool
	isLoop   bool // false = cycle mode, true = loop mode

	// Which TCP flag combo the server uses for data-bearing segments back
	// to the client. "PA" (default), "A" (bare ACK + data), "SA" (data
	// in SYN-ACK, TCP-Fast-Open style). See conf.Transport.CycleDataFlag.
	serverDataFlag string

	sendHandle *pcap.Handle
	recvHandle *pcap.Handle

	srcMAC net.HardwareAddr
	dstMAC net.HardwareAddr
	srcIP  net.IP // local IP

	// Client-only: the remote we're dialing.
	serverAddr *net.UDPAddr

	// Server-only: the port we listen on.
	listenPort uint16

	// Cycle state.
	cyclesMu sync.Mutex
	cycles   map[string]*cycle

	// Client-only loop mode: the currently active cycle, swapped on roll.
	activeLoopMu sync.Mutex
	activeLoop   *cycle

	// Client-only: port pool cursor (atomic for cheap allocation).
	portCursor atomic.Uint32

	// Outbound queue per client_ip on the SERVER side. When server's KCP
	// hands us a packet via WriteTo, we stash it here until the next
	// incoming cycle from that IP reaches its PA stage.
	serverOutMu sync.Mutex
	serverOut   map[string][][]byte // ip-string → []packet

	// Receive queue (delivered KCP packet bodies).
	readQueue chan readPacket

	// Debug counters.
	writeCount atomic.Uint64
	readCount  atomic.Uint64

	readDeadline  atomic.Value
	writeDeadline atomic.Value

	ctx    context.Context
	cancel context.CancelFunc
	closed atomic.Bool
}

// NewCycleServer creates a PacketConn in server mode for cycle/loop modes.
// The server's wire behavior is identical between the two — the mode flag
// only changes client-side cycle lifecycle.
func NewCycleServer(ctx context.Context, cfg *conf.Network, listenPort uint16, isLoop bool, serverDataFlag string) (*CycleConn, error) {
	cc, err := newCycleConn(ctx, cfg, true, isLoop, listenPort, nil, serverDataFlag)
	if err != nil {
		return nil, err
	}
	go cc.recvLoop()
	go cc.cycleSweeper()
	return cc, nil
}

// NewCycleClient creates a PacketConn in client mode for cycle/loop modes.
func NewCycleClient(ctx context.Context, cfg *conf.Network, serverAddr *net.UDPAddr, isLoop bool, serverDataFlag string) (*CycleConn, error) {
	cc, err := newCycleConn(ctx, cfg, false, isLoop, 0, serverAddr, serverDataFlag)
	if err != nil {
		return nil, err
	}
	var b [4]byte
	_, _ = rand.Read(b[:])
	cc.portCursor.Store(binary.BigEndian.Uint32(b[:]))
	go cc.recvLoop()
	go cc.cycleSweeper()
	if isLoop {
		go cc.loopRoller()
	}
	return cc, nil
}

func newCycleConn(ctx context.Context, cfg *conf.Network, isServer bool, isLoop bool, listenPort uint16, serverAddr *net.UDPAddr, serverDataFlag string) (*CycleConn, error) {
	sendH, err := openCyclePcap(cfg, pcap.DirectionOut)
	if err != nil {
		return nil, fmt.Errorf("cycle: open send pcap: %w", err)
	}
	recvH, err := openCyclePcap(cfg, pcap.DirectionIn)
	if err != nil {
		sendH.Close()
		return nil, fmt.Errorf("cycle: open recv pcap: %w", err)
	}

	var filter string
	if isServer {
		filter = fmt.Sprintf("tcp and dst port %d", listenPort)
	} else {
		// On client side, capture everything from the server's IP+port
		// regardless of which local port we sent from (rotating).
		filter = fmt.Sprintf("tcp and src host %s and src port %d", serverAddr.IP.String(), serverAddr.Port)
	}
	if err := recvH.SetBPFFilter(filter); err != nil {
		sendH.Close()
		recvH.Close()
		return nil, fmt.Errorf("cycle: set BPF %q: %w", filter, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	if serverDataFlag == "" {
		serverDataFlag = "PA"
	}
	cc := &CycleConn{
		cfg:            cfg,
		isServer:       isServer,
		isLoop:         isLoop,
		serverDataFlag: serverDataFlag,
		sendHandle:     sendH,
		recvHandle:     recvH,
		srcMAC:         cfg.Interface.HardwareAddr,
		serverAddr:     serverAddr,
		listenPort:     listenPort,
		cycles:         make(map[string]*cycle),
		serverOut:      make(map[string][][]byte),
		readQueue:      make(chan readPacket, cycleQueueCap),
		ctx:            ctx,
		cancel:         cancel,
	}
	if cfg.IPv4.Addr != nil {
		cc.srcIP = cfg.IPv4.Addr.IP
		cc.dstMAC = cfg.IPv4.Router
	}
	if cc.srcIP == nil {
		// Server tcp_carrier mode-like case where we accept any client IP
		// but still need an outgoing src for crafting responses. Fall back
		// to the first IPv4 on the interface.
		addrs, _ := cfg.Interface.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
				cc.srcIP = ipn.IP.To4()
				break
			}
		}
	}
	if cc.srcIP == nil {
		recvH.Close()
		sendH.Close()
		cancel()
		return nil, fmt.Errorf("cycle: could not determine source IPv4 on %s", cfg.Interface.Name)
	}
	if cc.dstMAC == nil {
		recvH.Close()
		sendH.Close()
		cancel()
		return nil, fmt.Errorf("cycle: gateway MAC required (network.ipv4.router_mac)")
	}
	return cc, nil
}

func openCyclePcap(cfg *conf.Network, dir pcap.Direction) (*pcap.Handle, error) {
	ifaceName := cfg.Interface.Name
	if runtime.GOOS == "windows" {
		ifaceName = cfg.GUID
	}
	inactive, err := pcap.NewInactiveHandle(ifaceName)
	if err != nil {
		return nil, err
	}
	defer inactive.CleanUp()
	_ = inactive.SetBufferSize(cfg.PCAP.Sockbuf)
	_ = inactive.SetSnapLen(65536)
	_ = inactive.SetPromisc(true)
	_ = inactive.SetTimeout(pcap.BlockForever)
	_ = inactive.SetImmediateMode(true)
	h, err := inactive.Activate()
	if err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" {
		_ = h.SetDirection(dir)
	}
	return h, nil
}

// allocPort returns the next source port from the rotating pool.
func (c *CycleConn) allocPort() uint16 {
	for range int(cyclePoolSize) {
		idx := c.portCursor.Add(1)
		port := cyclePoolBase + uint16(idx%uint32(cyclePoolSize))
		key := cycleKey(c.srcIP, port)
		c.cyclesMu.Lock()
		_, busy := c.cycles[key]
		c.cyclesMu.Unlock()
		if !busy {
			return port
		}
	}
	// Last resort: just pick a random port and hope.
	return cyclePoolBase + uint16(mrand.IntN(int(cyclePoolSize)))
}

// =====================================================================
//  net.PacketConn interface
// =====================================================================

func (c *CycleConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var deadlineCh <-chan time.Time
	if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer := time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadlineCh = timer.C
	}
	select {
	case <-c.ctx.Done():
		return 0, nil, net.ErrClosed
	case <-deadlineCh:
		return 0, nil, os.ErrDeadlineExceeded
	case pkt := <-c.readQueue:
		return copy(p, pkt.data), pkt.addr, nil
	}
}

func (c *CycleConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if c.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(p) > cycleMaxPacket {
		return 0, fmt.Errorf("cycle: packet %d > max %d", len(p), cycleMaxPacket)
	}
	if c.isServer {
		return c.serverWriteTo(p, addr)
	}
	return c.clientWriteTo(p, addr)
}

func (c *CycleConn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.cancel()
	if c.sendHandle != nil {
		c.sendHandle.Close()
	}
	if c.recvHandle != nil {
		c.recvHandle.Close()
	}
	return nil
}

func (c *CycleConn) LocalAddr() net.Addr {
	if c.isServer {
		return &net.UDPAddr{IP: c.srcIP, Port: int(c.listenPort)}
	}
	return &net.UDPAddr{IP: c.srcIP, Port: 0}
}

func (c *CycleConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	return nil
}
func (c *CycleConn) SetReadDeadline(t time.Time) error  { c.readDeadline.Store(t); return nil }
func (c *CycleConn) SetWriteDeadline(t time.Time) error { c.writeDeadline.Store(t); return nil }
func (c *CycleConn) SetDSCP(int) error                  { return nil }
func (c *CycleConn) SetClientTCPF(net.Addr, []conf.TCPF) {}

var _ net.PacketConn = (*CycleConn)(nil)

// =====================================================================
//  Client-side: WriteTo kicks off a new handshake cycle
// =====================================================================

func (c *CycleConn) clientWriteTo(p []byte, addr net.Addr) (int, error) {
	if c.isLoop {
		return c.loopWriteTo(p)
	}
	return c.cycleWriteTo(p)
}

// cycleWriteTo: handshake_cycle behavior — fresh cycle per KCP packet.
func (c *CycleConn) cycleWriteTo(p []byte) (int, error) {
	localPort := c.allocPort()
	remoteIP := c.serverAddr.IP
	remotePort := uint16(c.serverAddr.Port)

	var seqBytes [4]byte
	_, _ = rand.Read(seqBytes[:])
	ourSeq := binary.BigEndian.Uint32(seqBytes[:])

	cy := &cycle{
		localIP:    c.srcIP,
		localPort:  localPort,
		remoteIP:   remoteIP,
		remotePort: remotePort,
		mapKey:     cycleKey(c.srcIP, localPort),
		ourSeq:     ourSeq,
		state:      cycleSynSent,
		pending:    append([]byte(nil), p...),
		expires:    time.Now().Add(cycleTimeout),
	}

	c.cyclesMu.Lock()
	c.cycles[cy.key()] = cy
	c.cyclesMu.Unlock()

	if err := c.sendTCP(cy, tcpFlagsSYN, nil); err != nil {
		c.dropCycle(cy)
		return 0, err
	}
	wc := c.writeCount.Add(1)
	if wc <= 5 || wc%500 == 0 {
		flog.Debugf("cycle/client: cycle started localPort=%d wc=%d kcpLen=%d", localPort, wc, len(p))
	}
	return len(p), nil
}

// loopWriteTo: handshake_loop behavior — long-lived cycle, rolled by the
// loopRoller goroutine every loopRollInterval. WriteTo either sends on
// the active established cycle, or starts a fresh one if there isn't one.
func (c *CycleConn) loopWriteTo(p []byte) (int, error) {
	c.activeLoopMu.Lock()
	cy := c.activeLoop
	c.activeLoopMu.Unlock()

	// No active cycle yet, or current one is closed. Start a fresh
	// handshake and stash the payload to be sent when [SA] arrives.
	if cy == nil || cy.state == cycleClosed {
		return c.loopStartCycle(p)
	}

	// Active cycle is established — send the payload immediately as [PA].
	cy.theirSeq = cy.theirSeq // no-op, just for clarity
	if err := c.sendTCP(cy, tcpFlagsPSHACK, p); err != nil {
		flog.Debugf("loop/client: PA send failed: %v", err)
		return 0, err
	}
	cy.ourSeq += uint32(len(p))
	wc := c.writeCount.Add(1)
	if wc <= 5 || wc%500 == 0 {
		flog.Debugf("loop/client: PA on existing cycle localPort=%d wc=%d kcpLen=%d", cy.localPort, wc, len(p))
	}
	return len(p), nil
}

func (c *CycleConn) loopStartCycle(initialPayload []byte) (int, error) {
	localPort := c.allocPort()
	var seqBytes [4]byte
	_, _ = rand.Read(seqBytes[:])
	ourSeq := binary.BigEndian.Uint32(seqBytes[:])

	cy := &cycle{
		localIP:    c.srcIP,
		localPort:  localPort,
		remoteIP:   c.serverAddr.IP,
		remotePort: uint16(c.serverAddr.Port),
		mapKey:     cycleKey(c.srcIP, localPort),
		ourSeq:     ourSeq,
		state:      cycleSynSent,
		pending:    append([]byte(nil), initialPayload...),
		expires:    time.Now().Add(time.Hour), // long-lived; loopRoller manages rolls
	}
	c.cyclesMu.Lock()
	c.cycles[cy.key()] = cy
	c.cyclesMu.Unlock()
	c.activeLoopMu.Lock()
	c.activeLoop = cy
	c.activeLoopMu.Unlock()
	if err := c.sendTCP(cy, tcpFlagsSYN, nil); err != nil {
		c.dropCycle(cy)
		c.activeLoopMu.Lock()
		c.activeLoop = nil
		c.activeLoopMu.Unlock()
		return 0, err
	}
	wc := c.writeCount.Add(1)
	if wc <= 5 || wc%500 == 0 {
		flog.Debugf("loop/client: new cycle localPort=%d wc=%d kcpLen=%d", localPort, wc, len(initialPayload))
	}
	return len(initialPayload), nil
}

// loopRoller closes the current active cycle and forces a new handshake
// every loopRollInterval, so the carrier sees a stream of medium-lived
// connections instead of one long-lived flow.
func (c *CycleConn) loopRoller() {
	t := time.NewTicker(loopRollInterval)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-t.C:
			c.activeLoopMu.Lock()
			cy := c.activeLoop
			c.activeLoop = nil
			c.activeLoopMu.Unlock()
			if cy != nil && cy.state != cycleClosed {
				// Graceful close: FIN-ACK so the carrier sees a normal teardown.
				_ = c.sendTCP(cy, tcpFlagsFINACK, nil)
				cy.state = cycleClosed
				flog.Debugf("loop/client: rolled cycle localPort=%d", cy.localPort)
			}
		}
	}
}

// =====================================================================
//  Server-side: WriteTo queues data for the next inbound cycle from this client
// =====================================================================

func (c *CycleConn) serverWriteTo(p []byte, addr net.Addr) (int, error) {
	uaddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("cycle/server: WriteTo expects *net.UDPAddr, got %T", addr)
	}
	key := uaddr.IP.String()
	c.serverOutMu.Lock()
	c.serverOut[key] = append(c.serverOut[key], append([]byte(nil), p...))
	c.serverOutMu.Unlock()
	wc := c.writeCount.Add(1)
	if wc <= 5 || wc%500 == 0 {
		flog.Debugf("cycle/server: queued outbound for %s wc=%d kcpLen=%d", key, wc, len(p))
	}
	return len(p), nil
}

// popServerOutAll drains every queued KCP packet for the given client IP and
// returns them concatenated as a length-prefixed multi-packet stream:
//   [2-byte BE len][pkt1][2-byte BE len][pkt2]...
// The receiving cycleconn on the peer parses this same framing and delivers
// each packet to the KCP layer individually.
//
// Returns nil if the queue is empty. Honors mtu-derived cap on payload size
// so a single [PA] won't exceed what TCP/MTU allows.
func (c *CycleConn) popServerOutAll(ipKey string) []byte {
	const maxBundle = 1300 // leave headroom under typical 1500 MTU for IP+TCP+options
	c.serverOutMu.Lock()
	defer c.serverOutMu.Unlock()
	q := c.serverOut[ipKey]
	if len(q) == 0 {
		return nil
	}
	var out []byte
	consumed := 0
	for _, pkt := range q {
		need := 2 + len(pkt)
		if len(out)+need > maxBundle && len(out) > 0 {
			break
		}
		var lb [2]byte
		binary.BigEndian.PutUint16(lb[:], uint16(len(pkt)))
		out = append(out, lb[:]...)
		out = append(out, pkt...)
		consumed++
	}
	c.serverOut[ipKey] = q[consumed:]
	return out
}

// =====================================================================
//  Receive loop: parse pcap-captured packets and run the state machine
// =====================================================================

func (c *CycleConn) recvLoop() {
	for {
		if c.closed.Load() {
			return
		}
		data, _, err := c.recvHandle.ReadPacketData()
		if err != nil {
			if c.closed.Load() {
				return
			}
			flog.Debugf("cycle: recv error: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		ipL := pkt.NetworkLayer()
		if ipL == nil {
			continue
		}
		var srcIP, dstIP net.IP
		switch v := ipL.(type) {
		case *layers.IPv4:
			srcIP = v.SrcIP
			dstIP = v.DstIP
		default:
			continue
		}
		tcpL, ok := pkt.TransportLayer().(*layers.TCP)
		if !ok {
			continue
		}
		c.handleIncoming(srcIP, dstIP, tcpL, pkt.ApplicationLayer())
	}
}

func (c *CycleConn) handleIncoming(srcIP, dstIP net.IP, t *layers.TCP, app gopacket.ApplicationLayer) {
	var payload []byte
	if app != nil {
		payload = app.Payload()
	}
	if c.isServer {
		c.handleIncomingServer(srcIP, t, payload)
	} else {
		c.handleIncomingClient(srcIP, t, payload)
	}
}

func (c *CycleConn) handleIncomingClient(srcIP net.IP, t *layers.TCP, payload []byte) {
	// On client, key by our local port (= dst port of the incoming packet).
	key := cycleKey(c.srcIP, uint16(t.DstPort))
	c.cyclesMu.Lock()
	cy, exists := c.cycles[key]
	c.cyclesMu.Unlock()
	if !exists {
		// Stray packet for a cycle we no longer track. Ignore.
		return
	}

	switch {
	case t.SYN && t.ACK:
		// Accept SA only if we're actually waiting for one. A SA arriving
		// after the handshake completed is either a retransmit (harmless to
		// ignore) or a middlebox injection (dangerous to honor).
		if cy.state != cycleSynSent {
			return
		}
		// Validate ack: the carrier may inject SAs but can't fake our random
		// initial seq + 1 without observing the wire — and even if they're
		// observing, dropping the mismatched ones is cheap.
		if t.Ack != cy.ourSeq+1 {
			flog.Debugf("cycle/client: SA ack mismatch (got %d expected %d) for cy %s — dropping (likely injection)", t.Ack, cy.ourSeq+1, cy.key())
			return
		}
		// In "SA" data-flag mode the server piggybacks KCP data on the
		// SYN-ACK itself. Extract it before completing the handshake.
		if len(payload) > 0 {
			c.unpackAndDeliver(payload, c.serverAddr)
		}
		cy.theirSeq = t.Seq + uint32(len(payload))
		cy.ourSeq = t.Ack
		cy.state = cycleEstablished
		if cy.pending != nil {
			if err := c.sendTCP(cy, tcpFlagsPSHACK, cy.pending); err != nil {
				flog.Debugf("cycle/client: PA send failed for localPort=%d: %v", cy.localPort, err)
				c.dropCycle(cy)
				return
			}
			cy.ourSeq += uint32(len(cy.pending))
			cy.pending = nil
			cy.state = cycleDataDelivered
		}

	case t.ACK && !t.SYN && len(payload) > 0:
		// Server data-bearing segment. May be either [PA] (PSH-ACK with
		// payload, the default mode) or [.] (bare ACK with payload, the
		// "A" data-flag mode). Same handling — extract bundled KCP
		// packets and deliver to KCP. KCP's AEAD authenticates each
		// packet so any injection that survived to this point fails
		// integrity and gets dropped silently inside KCP.
		if cy.state != cycleEstablished && cy.state != cycleDataDelivered {
			return
		}
		c.unpackAndDeliver(payload, c.serverAddr)

	case t.ACK && !t.SYN && len(payload) == 0:
		// Bare ACK from server with no payload. Nothing to do.

	case t.RST:
		// The carrier may inject RSTs to forcibly kill flows. Don't
		// honor them — let the cycle time out via the sweeper instead.
		// (If the cycle is genuinely dead the sweeper will catch it
		// within cycleTimeout / loop's expires.)
		flog.Debugf("cycle/client: RST received for cy %s — ignoring (hostile-middlebox mitigation)", cy.key())
	}
}

func (c *CycleConn) handleIncomingServer(srcIP net.IP, t *layers.TCP, payload []byte) {
	// On server, key by the client's (remote) address.
	key := cycleKey(srcIP, uint16(t.SrcPort))
	c.cyclesMu.Lock()
	cy, exists := c.cycles[key]
	c.cyclesMu.Unlock()

	switch {
	case t.SYN && !t.ACK:
		// New cycle initiated by client.
		var seqBytes [4]byte
		_, _ = rand.Read(seqBytes[:])
		ourSeq := binary.BigEndian.Uint32(seqBytes[:])
		cy = &cycle{
			localIP:    c.srcIP,             // our IP (server's)
			localPort:  c.listenPort,         // our listen port
			remoteIP:   srcIP,                // client's IP
			remotePort: uint16(t.SrcPort),    // client's source port
			mapKey:     key,
			ourSeq:     ourSeq,
			theirSeq:   t.Seq,
			state:      cycleSynReceived,
			expires:    time.Now().Add(cycleTimeout),
		}
		c.cyclesMu.Lock()
		c.cycles[key] = cy
		c.cyclesMu.Unlock()
		// In "SA" data-flag mode the server piggybacks queued KCP data
		// into the SYN-ACK itself (TCP Fast Open style). This is
		// because some hostile carriers drop server→client packets
		// with payload UNLESS they're on this specific flag combo.
		var saBody []byte
		if c.serverDataFlag == "SA" {
			saBody = c.popServerOutAll(srcIP.String())
		}
		if err := c.sendTCP(cy, tcpFlagsSYNACK, saBody); err != nil {
			flog.Debugf("cycle/server: SA send failed for %s: %v", key, err)
			c.dropCycle(cy)
			return
		}
		cy.ourSeq += 1 + uint32(len(saBody)) // SYN consumes 1 seq slot, body adds its bytes

	case t.PSH && t.ACK && len(payload) > 0:
		if !exists {
			// PA without a known cycle for this peer — either we missed
			// the SYN (we wouldn't accept it then), or it's an injection.
			// Either way, ignore.
			return
		}
		// Don't accept PA on a brand-new cycle that hasn't seen an A or
		// reached established state. Real clients complete the handshake
		// before sending PA.
		if cy.state == cycleSynSent {
			return
		}
		cy.state = cycleDataDelivered
		c.deliverRead(payload, &net.UDPAddr{IP: srcIP, Port: 0})
		// Pick the flag for the server's data response per config. In "SA"
		// mode the data has already been delivered via the SYN-ACK back-
		// channel, so we send only a bare ACK here.
		var out []byte
		if c.serverDataFlag != "SA" {
			out = c.popServerOutAll(srcIP.String())
		}
		var flags tcpFlags
		var body []byte
		if out != nil {
			switch c.serverDataFlag {
			case "A":
				flags = tcpFlagsACK
			default: // "PA"
				flags = tcpFlagsPSHACK
			}
			body = out
		} else {
			flags = tcpFlagsACK
		}
		cy.theirSeq = t.Seq + uint32(len(payload))
		if err := c.sendTCP(cy, flags, body); err != nil {
			flog.Debugf("cycle/server: ACK send failed for %s: %v", key, err)
			return // don't drop on send failure — cycle may recover
		}
		cy.ourSeq += uint32(len(body))

	case t.ACK && !t.SYN && len(payload) == 0:
		if exists {
			cy.state = cycleEstablished
		}

	case t.RST:
		// Don't honor RST: hostile middleboxes inject these to kill flows.
		// Cycle will time out naturally if truly dead.
		if exists {
			flog.Debugf("cycle/server: RST received for cy %s — ignoring (hostile-middlebox mitigation)", key)
		}
	}
}

func (c *CycleConn) deliverRead(data []byte, addr *net.UDPAddr) {
	buf := append([]byte(nil), data...)
	rc := c.readCount.Add(1)
	if rc <= 5 || rc%500 == 0 {
		flog.Debugf("cycle: deliver read #%d from %s len=%d", rc, addr, len(data))
	}
	select {
	case c.readQueue <- readPacket{data: buf, addr: addr}:
	case <-c.ctx.Done():
	}
}

// unpackAndDeliver splits a length-prefixed multi-packet payload (see
// popServerOutAll) and delivers each contained KCP packet to the read queue.
func (c *CycleConn) unpackAndDeliver(payload []byte, addr *net.UDPAddr) {
	for len(payload) >= 2 {
		n := binary.BigEndian.Uint16(payload[:2])
		payload = payload[2:]
		if int(n) > len(payload) {
			flog.Debugf("cycle: malformed bundle (claim=%d remain=%d), dropping rest", n, len(payload))
			return
		}
		c.deliverRead(payload[:n], addr)
		payload = payload[n:]
	}
}

func (c *CycleConn) dropCycle(cy *cycle) {
	c.cyclesMu.Lock()
	delete(c.cycles, cy.key())
	c.cyclesMu.Unlock()
}

// cycleSweeper periodically evicts cycles that have aged out, freeing their
// ports for reuse and bounding memory.
func (c *CycleConn) cycleSweeper() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case now := <-t.C:
			c.cyclesMu.Lock()
			for k, cy := range c.cycles {
				if now.After(cy.expires) {
					delete(c.cycles, k)
				}
			}
			c.cyclesMu.Unlock()
		}
	}
}

// =====================================================================
//  TCP packet crafting
// =====================================================================

type tcpFlags uint8

const (
	tcpFlagsSYN    tcpFlags = 1 << iota // SYN
	tcpFlagsSYNACK                      // SYN+ACK
	tcpFlagsACK                         // ACK only
	tcpFlagsPSHACK                      // PSH+ACK (data)
	tcpFlagsFINACK                      // FIN+ACK
	tcpFlagsRST                         // RST
)

func (c *CycleConn) sendTCP(cy *cycle, flags tcpFlags, payload []byte) error {
	eth := &layers.Ethernet{
		SrcMAC:       c.srcMAC,
		DstMAC:       c.dstMAC,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip4 := &layers.IPv4{
		Version:  4,
		IHL:      5,
		TTL:      64,
		TOS:      0,
		Protocol: layers.IPProtocolTCP,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    cy.localIP,
		DstIP:    cy.remoteIP,
	}
	t := &layers.TCP{
		SrcPort: layers.TCPPort(cy.localPort),
		DstPort: layers.TCPPort(cy.remotePort),
		Window:  65535,
		Seq:     cy.ourSeq,
	}
	switch flags {
	case tcpFlagsSYN:
		t.SYN = true
		t.Options = synOptions()
	case tcpFlagsSYNACK:
		t.SYN = true
		t.ACK = true
		t.Ack = cy.theirSeq + 1
		// TCP Fast Open style: SYN-ACK can carry payload. We don't set
		// the TFO option header (it's a real-TCP feature with cookie
		// negotiation we don't need), but raw TCP allows data in any
		// flag combo. The receiver's pcap reader extracts payload by
		// IP+TCP length math, not by flag-aware parsing.
		t.Options = synOptions()
	case tcpFlagsACK:
		t.ACK = true
		t.Ack = cy.theirSeq
	case tcpFlagsPSHACK:
		t.PSH = true
		t.ACK = true
		t.Ack = cy.theirSeq + 1
	case tcpFlagsFINACK:
		t.FIN = true
		t.ACK = true
		t.Ack = cy.theirSeq
	case tcpFlagsRST:
		t.RST = true
	}
	t.SetNetworkLayerForChecksum(ip4)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip4, t, gopacket.Payload(payload)); err != nil {
		flog.Debugf("cycle/sendTCP: serialize error: %v", err)
		return fmt.Errorf("cycle: serialize: %w", err)
	}
	out := buf.Bytes()
	flog.Debugf("cycle/sendTCP: writing %d bytes flags=%d %s:%d→%s:%d seq=%d ack=%d",
		len(out), flags, cy.localIP, cy.localPort, cy.remoteIP, cy.remotePort, t.Seq, t.Ack)
	if err := c.sendHandle.WritePacketData(out); err != nil {
		flog.Debugf("cycle/sendTCP: WritePacketData error: %v", err)
		return err
	}
	return nil
}

func synOptions() []layers.TCPOption {
	return []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
	}
}
