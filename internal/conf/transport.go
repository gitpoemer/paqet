package conf

import (
	"fmt"
	"slices"
)

type Transport struct {
	Protocol string `yaml:"protocol"`
	Conn     int    `yaml:"conn"`
	TCPBuf   int    `yaml:"tcpbuf"`
	UDPBuf   int    `yaml:"udpbuf"`
	// UDPIdleTimeoutMS is the both-direction-quiet timeout in
	// milliseconds before a UDP relay stream is torn down. 0 ⇒
	// use buffer.DefaultUDPIdleTimeout (30s). Lower for DNS-heavy
	// deployments, higher for sticky long-lived UDP (QUIC, MTProto).
	UDPIdleTimeoutMS int  `yaml:"udpidletimeout"`
	// EgressMark is the SO_MARK (Linux fwmark) stamped on server-side
	// egress sockets — the TCP/UDP connections the server opens to the
	// real targets. 0 ⇒ disabled (normal routing). Set it (e.g. 1) to
	// pair with a policy-routing rule that sends marked packets out a
	// WARP/WireGuard interface, so only forwarded traffic egresses via
	// Cloudflare while the tunnel's own control traffic stays on the
	// real interface. Linux-only; ignored on other platforms.
	EgressMark uint32 `yaml:"egress_mark"`
	KCP        *KCP   `yaml:"kcp"`
}

func (t *Transport) setDefaults(role string) {
	if t.Conn == 0 {
		t.Conn = 1
	}

	if t.TCPBuf == 0 {
		t.TCPBuf = 8 * 1024
	}
	if t.TCPBuf < 4*1024 {
		t.TCPBuf = 4 * 1024
	}
	if t.UDPBuf == 0 {
		t.UDPBuf = 4 * 1024
	}
	if t.UDPBuf < 2*1024 {
		t.UDPBuf = 2 * 1024
	}
	// UDPIdleTimeoutMS=0 keeps the buffer-package default; only
	// validate ranges if the user explicitly set something.
	if t.UDPIdleTimeoutMS != 0 && t.UDPIdleTimeoutMS < 500 {
		t.UDPIdleTimeoutMS = 500
	}

	switch t.Protocol {
	case "kcp":
		t.KCP.setDefaults(role)
	}
}

func (t *Transport) validate() []error {
	var errors []error

	validProtocols := []string{"kcp"}
	if !slices.Contains(validProtocols, t.Protocol) {
		errors = append(errors, fmt.Errorf("transport protocol must be one of: %v", validProtocols))
	}

	if t.Conn < 1 || t.Conn > 256 {
		errors = append(errors, fmt.Errorf("KCP conn must be between 1-256 connections"))
	}
	// EgressMark is a uint32, so any value is in range (0 = disabled); no
	// bounds check needed. yaml rejects negatives / overflow on unmarshal.

	switch t.Protocol {
	case "kcp":
		errors = append(errors, t.KCP.validate()...)
	}

	return errors
}
