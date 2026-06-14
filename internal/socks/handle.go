package socks

import (
	"context"
	"paqet/internal/client"
	"time"
)

type Handler struct {
	client      *client.Client
	ctx         context.Context
	udpIdleTimeout time.Duration // 0 ⇒ use buffer.DefaultUDPIdleTimeout
}
