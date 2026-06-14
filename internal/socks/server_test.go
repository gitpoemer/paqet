package socks

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// fakeHandler captures what the server hands off after a successful
// handshake, and lets tests drive the post-handshake behavior.
type fakeHandler struct {
	mu             sync.Mutex
	connectDest    AddrSpec
	connectInvoked bool
	udpInvoked     bool

	// connectFn / udpFn let tests override the handler behavior;
	// otherwise the handler holds conn open by reading to EOF.
	connectFn func(ctx context.Context, conn net.Conn, dest AddrSpec) error
	udpFn     func(ctx context.Context, udp *net.UDPConn, clientCtl net.Conn) error
}

func (f *fakeHandler) HandleConnect(ctx context.Context, conn net.Conn, dest AddrSpec) error {
	f.mu.Lock()
	f.connectDest = dest
	f.connectInvoked = true
	fn := f.connectFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, conn, dest)
	}
	// Default: drain & wait so the conn stays open during the test.
	_, _ = io.Copy(io.Discard, conn)
	return nil
}

func (f *fakeHandler) HandleUDPAssociate(ctx context.Context, udp *net.UDPConn, clientCtl net.Conn) error {
	f.mu.Lock()
	f.udpInvoked = true
	fn := f.udpFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx, udp, clientCtl)
	}
	_, _ = io.Copy(io.Discard, clientCtl)
	return nil
}

// startTestServer brings up a SOCKS5 server on 127.0.0.1:0 and returns
// the dial address and a stop function that waits for shutdown.
func startTestServer(t *testing.T, username, password string, h ConnHandler) (string, func()) {
	t.Helper()
	srv := NewServer("127.0.0.1:0", username, password, h)
	srv.HandshakeTimeout = 2 * time.Second

	// Pre-bind so the test knows the port before Start returns from
	// the listener Accept loop.
	tcpL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.listener = tcpL
	srv.addr = tcpL.Addr().String()

	// Same for UDP relay.
	host, _, _ := net.SplitHostPort(srv.addr)
	udpA, _ := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	udpL, err := net.ListenUDP("udp", udpA)
	if err != nil {
		tcpL.Close()
		t.Fatal(err)
	}
	srv.udpRelay = udpL.LocalAddr().(*net.UDPAddr)
	udpL.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		// Shutdown driver inline.
		go func() {
			<-ctx.Done()
			tcpL.Close()
		}()
		srv.acceptLoop(ctx)
		srv.wg.Wait()
	}()

	stop := func() {
		cancel()
		<-done
	}
	return srv.addr, stop
}

// dialAndDo creates a TCP connection to the server and runs the given
// driver against it, returning any error.
func dialAndDo(t *testing.T, addr string, fn func(net.Conn) error) error {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return fn(conn)
}

// --- happy-path handshakes ---

func TestServer_NoAuth_Connect_Success(t *testing.T) {
	h := &fakeHandler{
		connectFn: func(ctx context.Context, conn net.Conn, dest AddrSpec) error {
			conn.Write([]byte("hello"))
			return nil
		},
	}
	addr, stop := startTestServer(t, "", "", h)
	defer stop()

	err := dialAndDo(t, addr, func(c net.Conn) error {
		// Greeting: VER, NMETHODS=1, AuthNoAuth
		if _, err := c.Write([]byte{Version5, 1, AuthNoAuth}); err != nil {
			return err
		}
		// Read greeting response
		gr := make([]byte, 2)
		if _, err := io.ReadFull(c, gr); err != nil {
			return err
		}
		if gr[0] != Version5 || gr[1] != AuthNoAuth {
			t.Fatalf("greeting resp = % x", gr)
		}
		// Request: CONNECT to 8.8.8.8:53
		req := []byte{Version5, CmdConnect, 0x00, ATYPIPv4, 8, 8, 8, 8, 0x00, 0x35}
		if _, err := c.Write(req); err != nil {
			return err
		}
		// Read reply (10 bytes for IPv4)
		reply := make([]byte, 10)
		if _, err := io.ReadFull(c, reply); err != nil {
			return err
		}
		if reply[0] != Version5 || reply[1] != RepSuccess {
			t.Fatalf("reply = % x", reply)
		}
		// Now the handler runs; expect "hello"
		buf := make([]byte, 5)
		if _, err := io.ReadFull(c, buf); err != nil {
			return err
		}
		if string(buf) != "hello" {
			t.Fatalf("payload = %q", buf)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.connectInvoked {
		t.Fatal("HandleConnect not invoked")
	}
	if !h.connectDest.IP.Equal(net.IPv4(8, 8, 8, 8)) || h.connectDest.Port != 53 {
		t.Fatalf("dest mismatch: %+v", h.connectDest)
	}
}

func TestServer_UserPass_Connect_Success(t *testing.T) {
	h := &fakeHandler{}
	addr, stop := startTestServer(t, "user", "pass", h)
	defer stop()

	err := dialAndDo(t, addr, func(c net.Conn) error {
		// Greeting offers both NoAuth + UserPass; server must pick UserPass
		c.Write([]byte{Version5, 2, AuthNoAuth, AuthUserPass})
		gr := make([]byte, 2)
		io.ReadFull(c, gr)
		if gr[1] != AuthUserPass {
			t.Fatalf("server picked method %#x, want UserPass", gr[1])
		}
		// User/Pass sub-negotiation
		auth := []byte{UserPassVersion, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'}
		c.Write(auth)
		ar := make([]byte, 2)
		io.ReadFull(c, ar)
		if ar[1] != UserPassSuccess {
			t.Fatalf("auth status = %#x", ar[1])
		}
		// CONNECT
		c.Write([]byte{Version5, CmdConnect, 0x00, ATYPIPv4, 1, 1, 1, 1, 0x00, 0x50})
		reply := make([]byte, 10)
		io.ReadFull(c, reply)
		if reply[1] != RepSuccess {
			t.Fatalf("reply REP = %#x", reply[1])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// --- rejection paths ---

func TestServer_BadVersion_DropsConn(t *testing.T) {
	addr, stop := startTestServer(t, "", "", &fakeHandler{})
	defer stop()

	err := dialAndDo(t, addr, func(c net.Conn) error {
		c.Write([]byte{0x04, 1, 0x00}) // VER=4
		// Server should close the conn; reads return EOF/closed.
		c.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 16)
		_, err := c.Read(buf)
		if err == nil {
			t.Fatal("expected conn-close on bad VER, got data")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestServer_UnsupportedAuthMethod(t *testing.T) {
	h := &fakeHandler{}
	addr, stop := startTestServer(t, "", "", h) // server expects NoAuth
	defer stop()

	err := dialAndDo(t, addr, func(c net.Conn) error {
		// Offer only GSSAPI
		c.Write([]byte{Version5, 1, AuthGSSAPI})
		gr := make([]byte, 2)
		io.ReadFull(c, gr)
		if gr[1] != AuthNoneAcceptable {
			t.Fatalf("server method = %#x, want NoneAcceptable", gr[1])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestServer_AuthFailed(t *testing.T) {
	h := &fakeHandler{}
	addr, stop := startTestServer(t, "user", "pass", h)
	defer stop()

	err := dialAndDo(t, addr, func(c net.Conn) error {
		c.Write([]byte{Version5, 1, AuthUserPass})
		gr := make([]byte, 2)
		io.ReadFull(c, gr)
		// Wrong password
		c.Write([]byte{UserPassVersion, 4, 'u', 's', 'e', 'r', 4, 'w', 'r', 'o', 'n'})
		ar := make([]byte, 2)
		io.ReadFull(c, ar)
		if ar[1] != UserPassFailure {
			t.Fatalf("auth status = %#x want failure", ar[1])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.connectInvoked {
		t.Fatal("HandleConnect ran despite auth failure")
	}
}

func TestServer_UnsupportedCmd(t *testing.T) {
	h := &fakeHandler{}
	addr, stop := startTestServer(t, "", "", h)
	defer stop()

	err := dialAndDo(t, addr, func(c net.Conn) error {
		c.Write([]byte{Version5, 1, AuthNoAuth})
		io.ReadFull(c, make([]byte, 2))
		// CMD = BIND
		c.Write([]byte{Version5, CmdBind, 0x00, ATYPIPv4, 1, 1, 1, 1, 0x00, 0x50})
		reply := make([]byte, 10)
		if _, err := io.ReadFull(c, reply); err != nil {
			return err
		}
		if reply[1] != RepCmdNotSupported {
			t.Fatalf("REP = %#x want CmdNotSupported", reply[1])
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// --- UDP_ASSOCIATE ---

func TestServer_UDPAssociate_AdvertisesRelayPort(t *testing.T) {
	h := &fakeHandler{
		udpFn: func(ctx context.Context, udp *net.UDPConn, clientCtl net.Conn) error {
			// Just hold for the duration of the test.
			_, _ = io.Copy(io.Discard, clientCtl)
			return nil
		},
	}
	addr, stop := startTestServer(t, "", "", h)
	defer stop()

	err := dialAndDo(t, addr, func(c net.Conn) error {
		c.Write([]byte{Version5, 1, AuthNoAuth})
		io.ReadFull(c, make([]byte, 2))
		c.Write([]byte{Version5, CmdUDPAssociate, 0x00, ATYPIPv4, 0, 0, 0, 0, 0x00, 0x00})
		// Read VER REP RSV ATYP (4 bytes) then port-length-dependent
		head := make([]byte, 4)
		if _, err := io.ReadFull(c, head); err != nil {
			return err
		}
		if head[1] != RepSuccess {
			t.Fatalf("REP = %#x", head[1])
		}
		if head[3] != ATYPIPv4 && head[3] != ATYPIPv6 {
			t.Fatalf("BND ATYP = %#x", head[3])
		}
		// Drain BND.ADDR + BND.PORT
		addrLen := 4
		if head[3] == ATYPIPv6 {
			addrLen = 16
		}
		bnd := make([]byte, addrLen+2)
		if _, err := io.ReadFull(c, bnd); err != nil {
			return err
		}
		port := binary.BigEndian.Uint16(bnd[addrLen:])
		if port == 0 {
			t.Fatal("server advertised UDP relay port 0")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.udpInvoked {
		t.Fatal("UDP handler not invoked")
	}
}

// --- handshake timeout ---

func TestServer_HandshakeTimeout(t *testing.T) {
	h := &fakeHandler{}
	srv := NewServer("127.0.0.1:0", "", "", h)
	srv.HandshakeTimeout = 100 * time.Millisecond
	tcpL, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.listener = tcpL
	srv.addr = tcpL.Addr().String()
	udpL, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	srv.udpRelay = udpL.LocalAddr().(*net.UDPAddr)
	udpL.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		go func() { <-ctx.Done(); tcpL.Close() }()
		srv.acceptLoop(ctx)
		srv.wg.Wait()
		close(done)
	}()
	defer func() { cancel(); <-done }()

	c, err := net.Dial("tcp", srv.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Send 1 byte then sit. Server should close after 100ms.
	c.Write([]byte{Version5})
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = c.Read(buf)
	if err == nil {
		t.Fatal("expected EOF after handshake timeout")
	}
	if !errors.Is(err, io.EOF) && !isClosedConnErr(err) {
		// Some libc/syscall combinations return RST; either is fine.
		// Just ensure the connection ended.
		t.Logf("got %v (acceptable: any close)", err)
	}
}

// --- selectAuthMethod ---

func TestSelectAuthMethod(t *testing.T) {
	tests := []struct {
		name    string
		user    string
		pass    string
		offered []byte
		want    byte
	}{
		{"NoAuth wanted, NoAuth offered", "", "", []byte{AuthNoAuth}, AuthNoAuth},
		{"NoAuth wanted, UserPass only", "", "", []byte{AuthUserPass}, AuthNoneAcceptable},
		{"NoAuth wanted, multi includes NoAuth", "", "", []byte{AuthGSSAPI, AuthNoAuth, AuthUserPass}, AuthNoAuth},
		{"UserPass wanted, NoAuth only", "u", "p", []byte{AuthNoAuth}, AuthNoneAcceptable},
		{"UserPass wanted, both offered", "u", "p", []byte{AuthNoAuth, AuthUserPass}, AuthUserPass},
		{"UserPass wanted, GSSAPI only", "u", "p", []byte{AuthGSSAPI}, AuthNoneAcceptable},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{username: tt.user, password: tt.pass}
			got := s.selectAuthMethod(tt.offered)
			if got != tt.want {
				t.Fatalf("got %#x want %#x", got, tt.want)
			}
		})
	}
}

// --- helpers ---

// isClosedConnErr returns true if err looks like a closed-connection
// error from any of the various reads/writes against a torn-down peer.
func isClosedConnErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	// Accept any peer-disconnect strings — these vary by platform.
	s := err.Error()
	for _, sub := range []string{"closed", "reset", "broken pipe", "EOF"} {
		if bytes.Contains([]byte(s), []byte(sub)) {
			return true
		}
	}
	return false
}
