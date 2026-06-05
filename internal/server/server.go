package server

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
)

type Server struct {
	cfg   *conf.Conf
	pConn net.PacketConn
	wg    sync.WaitGroup
}

func New(cfg *conf.Conf) (*Server, error) {
	s := &Server{
		cfg: cfg,
	}

	return s, nil
}

func (s *Server) Start() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		flog.Infof("Shutdown signal received, initiating graceful shutdown...")
		cancel()
	}()

	var pConn net.PacketConn
	switch s.cfg.Transport.Mode {
	case "tcp_carrier":
		tcpAddr := &net.TCPAddr{IP: s.cfg.Listen.Addr.IP, Port: s.cfg.Listen.Addr.Port}
		tc, err := socket.NewTCPServer(ctx, tcpAddr)
		if err != nil {
			return fmt.Errorf("could not create tcp-carrier listener: %w", err)
		}
		pConn = tc
		flog.Infof("Server started in tcp_carrier mode - listening for TCP on :%d", s.cfg.Listen.Addr.Port)
	case "handshake_cycle", "handshake_loop":
		s.cfg.Network.Port = s.cfg.Listen.Addr.Port
		isLoop := s.cfg.Transport.Mode == "handshake_loop"
		cc, err := socket.NewCycleServer(ctx, &s.cfg.Network, uint16(s.cfg.Listen.Addr.Port), isLoop, s.cfg.Transport.CycleDataFlag)
		if err != nil {
			return fmt.Errorf("could not create %s listener: %w", s.cfg.Transport.Mode, err)
		}
		pConn = cc
		flog.Infof("Server started in %s mode (cycle_data_flag=%s) - listening on :%d", s.cfg.Transport.Mode, s.cfg.Transport.CycleDataFlag, s.cfg.Listen.Addr.Port)
	default:
		// "raw" or empty: the original pcap-based transport.
		pc, err := socket.New(ctx, &s.cfg.Network)
		if err != nil {
			return fmt.Errorf("could not create raw packet conn: %w", err)
		}
		pConn = pc
		flog.Infof("Server started - listening for packets on :%d", s.cfg.Listen.Addr.Port)
	}
	s.pConn = pConn

	listener, err := kcp.Listen(s.cfg.Transport.KCP, pConn)
	if err != nil {
		return fmt.Errorf("could not start KCP listener: %w", err)
	}
	defer listener.Close()

	s.wg.Go(func() {
		s.listen(ctx, listener)
	})

	s.wg.Wait()
	flog.Infof("Server shutdown completed")
	return nil
}

func (s *Server) listen(ctx context.Context, listener tnet.Listener) {
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		conn, err := listener.Accept()
		if err != nil {
			flog.Errorf("failed to accept connection: %v", err)
			continue
		}
		flog.Infof("accepted new connection from %s (local: %s)", conn.RemoteAddr(), conn.LocalAddr())

		s.wg.Go(func() {
			defer conn.Close()
			s.handleConn(ctx, conn)
		})
	}
}
