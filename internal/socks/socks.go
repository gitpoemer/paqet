package socks

import (
	"context"
	"paqet/internal/client"
	"paqet/internal/conf"
	"paqet/internal/flog"
)

// SOCKS5 is the entry-point wrapper retained so the rest of the
// codebase (cmd/run, etc.) keeps its existing Start signature.
// The actual server is in Server.
type SOCKS5 struct {
	handle *Handler
	server *Server
}

func New(c *client.Client) (*SOCKS5, error) {
	return &SOCKS5{handle: &Handler{client: c}}, nil
}

func (s *SOCKS5) Start(ctx context.Context, cfg conf.SOCKS5) error {
	s.handle.ctx = ctx
	addr := cfg.Listen.String()
	s.server = NewServer(addr, cfg.Username, cfg.Password, s.handle)
	go func() {
		if err := s.server.Start(ctx); err != nil {
			flog.Errorf("SOCKS5 server stopped: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		s.server.Stop()
	}()
	return nil
}
