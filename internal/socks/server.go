package socks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"paqet/internal/flog"
	"sync"
	"time"
)

// Server is the minimal hand-rolled SOCKS5 server that replaces the
// previous txthinking/socks5 dependency. It serializes the listen
// loop and dispatches each accepted TCP connection to handleConn.
//
// Design choices:
//   - One goroutine per accepted TCP connection. The actual relay
//     (after handshake) reuses pool buffers via buffer.RelayBidi so
//     the per-connection goroutine cost is the only allocation.
//   - UDP_ASSOCIATE allocates a fresh ephemeral UDP socket per
//     association. SOCKS5 RFC 1928 §6 requires that the UDP relay
//     close when the associated TCP control conn closes; the TCP
//     handler holds the lifetime.
//   - No TLS. SOCKS5 wraps cleartext on loopback in production.
//   - Auth: NoAuth and UserPass per RFC 1929. If the config sets
//     Username/Password, we REQUIRE UserPass; otherwise we accept
//     NoAuth only.
//
// Handshake bounded by HandshakeTimeout so a malicious or hung peer
// can't pin a goroutine forever during the negotiation phase. The
// timeout is removed before entering the long-lived relay path.
type Server struct {
	addr     string
	username string
	password string
	handler  ConnHandler

	listener net.Listener
	udpRelay *net.UDPAddr

	// HandshakeTimeout bounds the time spent reading the greeting,
	// auth, and request from the client. Once the relay starts, the
	// deadline is cleared.
	HandshakeTimeout time.Duration

	wg   sync.WaitGroup
	once sync.Once
	done chan struct{}
}

// ConnHandler is what the SOCKS5 server hands a successfully
// negotiated request to. The connection is post-reply (a SUCCESS
// REP has already been written for CONNECT, or BND.ADDR has been
// sent for UDP_ASSOCIATE).
//
// CONNECT: HandleConnect implements the actual TCP relay. The
// server's job is done — handler owns conn from here.
//
// UDP_ASSOCIATE: HandleUDPAssociate is called once per UDP_ASSOCIATE
// request. The TCP control conn is held open by the SOCKS5 server
// (it returns to the caller via reading io.Discard on conn until
// EOF). The handler runs the actual UDP datagram relay using the
// provided udp listener.
type ConnHandler interface {
	HandleConnect(ctx context.Context, conn net.Conn, dest AddrSpec) error
	HandleUDPAssociate(ctx context.Context, udp *net.UDPConn, clientCtl net.Conn) error
}

// NewServer wires a fresh SOCKS5 server. Call Start to begin
// accepting. Username/Password "" "" disables UserPass auth and
// requires NoAuth from clients.
func NewServer(addr, username, password string, handler ConnHandler) *Server {
	return &Server{
		addr:             addr,
		username:         username,
		password:         password,
		handler:          handler,
		HandshakeTimeout: 10 * time.Second,
		done:             make(chan struct{}),
	}
}

// Start binds the TCP listener and the UDP relay socket, then runs
// the accept loop. Returns on listener.Accept error (treated as
// shutdown) or on Stop.
func (s *Server) Start(ctx context.Context) error {
	tcpListener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("socks5: bind TCP %s: %w", s.addr, err)
	}
	s.listener = tcpListener

	// Bind a UDP socket on the same interface for UDP relay. The
	// UDP listener address gets returned in the UDP_ASSOCIATE reply
	// as BND.ADDR.
	host, _, err := net.SplitHostPort(s.addr)
	if err != nil {
		tcpListener.Close()
		return fmt.Errorf("socks5: split host/port %s: %w", s.addr, err)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		tcpListener.Close()
		return fmt.Errorf("socks5: resolve UDP %s: %w", host, err)
	}
	udpListen, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		tcpListener.Close()
		return fmt.Errorf("socks5: bind UDP %s: %w", host, err)
	}
	s.udpRelay = udpListen.LocalAddr().(*net.UDPAddr)
	udpListen.Close() // we only needed the port reservation for advertising; per-association sockets reopen

	flog.Infof("SOCKS5 server listening on tcp:%s udp-relay:%s",
		tcpListener.Addr(), s.udpRelay)

	// Shutdown driver: cancel ctx → close listener → accept loop exits.
	go func() {
		select {
		case <-ctx.Done():
		case <-s.done:
		}
		tcpListener.Close()
	}()

	s.acceptLoop(ctx)
	s.wg.Wait()
	return nil
}

// Stop initiates shutdown. Safe to call concurrently; idempotent.
func (s *Server) Stop() {
	s.once.Do(func() {
		close(s.done)
		if s.listener != nil {
			s.listener.Close()
		}
	})
}

func (s *Server) acceptLoop(ctx context.Context) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient accept error: log and retry. Don't busy-loop.
			flog.Errorf("SOCKS5 accept: %v", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer conn.Close()
			if err := s.handleConn(ctx, conn); err != nil && !errors.Is(err, net.ErrClosed) {
				flog.Debugf("SOCKS5 conn %s: %v", conn.RemoteAddr(), err)
			}
		}()
	}
}

// handleConn drives the per-connection handshake then dispatches.
// HandshakeTimeout bounds the greeting → auth → request phase; it's
// cleared before the relay starts.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) error {
	if s.HandshakeTimeout > 0 {
		conn.SetDeadline(time.Now().Add(s.HandshakeTimeout))
	}

	// --- Greeting ---
	greet, err := ReadGreeting(conn)
	if err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	method := s.selectAuthMethod(greet.Methods)
	if err := WriteGreetingResponse(conn, method); err != nil {
		return fmt.Errorf("greeting response: %w", err)
	}
	if method == AuthNoneAcceptable {
		return ErrUnsupportedAuth
	}

	// --- Auth ---
	if method == AuthUserPass {
		req, err := ReadUserPassRequest(conn)
		if err != nil {
			_ = WriteUserPassResponse(conn, UserPassFailure)
			return fmt.Errorf("userpass: %w", err)
		}
		if req.Username != s.username || req.Password != s.password {
			_ = WriteUserPassResponse(conn, UserPassFailure)
			return ErrAuthFailed
		}
		if err := WriteUserPassResponse(conn, UserPassSuccess); err != nil {
			return fmt.Errorf("userpass response: %w", err)
		}
	}

	// --- Request ---
	req, err := ReadRequest(conn)
	if err != nil {
		_ = WriteReply(conn, RepGeneralFailure, AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4zero}, nil)
		return fmt.Errorf("request: %w", err)
	}

	// Clear handshake deadline before entering long-lived relay.
	conn.SetDeadline(time.Time{})

	switch req.Cmd {
	case CmdConnect:
		// Reply BND.ADDR = our listening side of the conn. Many
		// clients ignore the value but RFC says we must send it.
		bnd := AddrSpecFromTCP(conn.LocalAddr().(*net.TCPAddr))
		if err := WriteReply(conn, RepSuccess, bnd, nil); err != nil {
			return fmt.Errorf("connect reply: %w", err)
		}
		return s.handler.HandleConnect(ctx, conn, req.Dest)

	case CmdUDPAssociate:
		// Allocate a fresh UDP socket for this association on the
		// same host:0 the advertised relay used. Per RFC §6, the
		// allocation lives as long as the TCP control conn.
		udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.udpRelay.IP.String(), "0"))
		if err != nil {
			_ = WriteReply(conn, RepGeneralFailure, AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4zero}, nil)
			return fmt.Errorf("udp resolve: %w", err)
		}
		udp, err := net.ListenUDP("udp", udpAddr)
		if err != nil {
			_ = WriteReply(conn, RepGeneralFailure, AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4zero}, nil)
			return fmt.Errorf("udp bind: %w", err)
		}
		defer udp.Close()
		bnd := AddrSpecFromUDP(udp.LocalAddr().(*net.UDPAddr))
		if err := WriteReply(conn, RepSuccess, bnd, nil); err != nil {
			return fmt.Errorf("udp_assoc reply: %w", err)
		}
		return s.handler.HandleUDPAssociate(ctx, udp, conn)

	default:
		bnd := AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4zero}
		_ = WriteReply(conn, RepCmdNotSupported, bnd, nil)
		return ErrUnsupportedCmd
	}
}

// selectAuthMethod picks the strongest acceptable auth method from
// the client's offered list, matched against our config. If
// Username/Password is set, only UserPass is accepted; otherwise
// only NoAuth is accepted.
func (s *Server) selectAuthMethod(offered []byte) byte {
	wantUserPass := s.username != "" || s.password != ""
	for _, m := range offered {
		switch m {
		case AuthUserPass:
			if wantUserPass {
				return AuthUserPass
			}
		case AuthNoAuth:
			if !wantUserPass {
				return AuthNoAuth
			}
		}
	}
	return AuthNoneAcceptable
}
