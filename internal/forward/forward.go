package forward

import (
	"context"
	"fmt"
	"net"
	"paqet/internal/client"
	"paqet/internal/flog"
	"sync"
)

type Forward struct {
	client     *client.Client
	listenAddr string
	targetAddr string
	wg         sync.WaitGroup
}

func New(client *client.Client, listenAddr, targetAddr string) (*Forward, error) {
	return &Forward{
		client:     client,
		listenAddr: listenAddr,
		targetAddr: targetAddr,
	}, nil
}

func (f *Forward) Start(ctx context.Context, protocol string) error {
	flog.Debugf("starting %s forwarder: %s -> %s", protocol, f.listenAddr, f.targetAddr)
	switch protocol {
	case "tcp":
		return f.startTCP(ctx)
	case "udp":
		return f.startUDP(ctx)
	default:
		flog.Errorf("unsupported protocol: %s", protocol)
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}
}

// startTCP binds the listen socket synchronously and surfaces bind errors
// to the caller (Start), so a busy/permission-denied port fails loudly
// instead of returning nil and dying inside a goroutine. Matches upstream
// 25cb186. Only the accept loop runs in the background.
func (f *Forward) startTCP(ctx context.Context) error {
	listener, err := net.Listen("tcp", f.listenAddr)
	if err != nil {
		flog.Errorf("failed to bind TCP socket on %s: %v", f.listenAddr, err)
		return err
	}
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	flog.Infof("TCP forwarder listening on %s -> %s", f.listenAddr, f.targetAddr)
	f.wg.Go(func() {
		if err := f.serveTCP(ctx, listener); err != nil {
			flog.Debugf("TCP forwarder stopped with: %v", err)
		}
	})
	return nil
}

// startUDP binds synchronously and surfaces bind errors, mirroring startTCP.
func (f *Forward) startUDP(ctx context.Context) error {
	laddr, err := net.ResolveUDPAddr("udp", f.listenAddr)
	if err != nil {
		flog.Errorf("failed to resolve UDP listen address '%s': %v", f.listenAddr, err)
		return err
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		flog.Errorf("failed to bind UDP socket on %s: %v", laddr, err)
		return err
	}
	go func() {
		<-ctx.Done()
		conn.Close()
	}()
	flog.Infof("UDP forwarder listening on %s -> %s", laddr, f.targetAddr)
	f.wg.Go(func() {
		f.serveUDP(ctx, conn)
	})
	return nil
}
