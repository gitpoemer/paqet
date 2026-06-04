package client

import (
	"context"
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/protocol"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
	"time"
)

type timedConn struct {
	cfg    *conf.Conf
	conn   tnet.Conn
	expire time.Time
	ctx    context.Context
}

func newTimedConn(ctx context.Context, cfg *conf.Conf) (*timedConn, error) {
	var err error
	tc := timedConn{cfg: cfg, ctx: ctx}
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}

	return &tc, nil
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	switch tc.cfg.Transport.Mode {
	case "tcp_carrier":
		srv := tc.cfg.Server.Addr
		tcpAddr := &net.TCPAddr{IP: srv.IP, Port: srv.Port, Zone: srv.Zone}
		pConn, err := socket.NewTCPClient(tc.ctx, tcpAddr)
		if err != nil {
			return nil, fmt.Errorf("could not create tcp-carrier conn: %w", err)
		}
		conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, pConn)
		if err != nil {
			return nil, err
		}
		return conn, nil

	case "handshake_cycle":
		netCfg := tc.cfg.Network
		pConn, err := socket.NewCycleClient(tc.ctx, &netCfg, tc.cfg.Server.Addr)
		if err != nil {
			return nil, fmt.Errorf("could not create cycle conn: %w", err)
		}
		conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, pConn)
		if err != nil {
			return nil, err
		}
		// handshake_cycle ignores per-client flag overrides — flag pattern
		// is built into the cycle state machine.
		return conn, nil
	}

	netCfg := tc.cfg.Network
	pConn, err := socket.New(tc.ctx, &netCfg)
	if err != nil {
		return nil, fmt.Errorf("could not create packet conn: %w", err)
	}

	conn, err := kcp.Dial(tc.cfg.Server.Addr, tc.cfg.Transport.KCP, pConn)
	if err != nil {
		return nil, err
	}
	err = tc.sendTCPF(conn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (tc *timedConn) sendTCPF(conn tnet.Conn) error {
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.cfg.Network.TCP.RF}
	err = p.Write(strm)
	if err != nil {
		return err
	}
	return nil
}

func (tc *timedConn) close() {
	if tc.conn != nil {
		tc.conn.Close()
	}
}
