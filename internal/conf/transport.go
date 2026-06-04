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
	// TCPCarrier switches the underlying packet transport from pcap-based
	// raw-TCP injection to real kernel TCP sockets. Equivalent to mode="tcp_carrier".
	TCPCarrier bool `yaml:"tcp_carrier"`
	// Mode selects the wire transport. Values:
	//   ""             — legacy default (pcap-injected raw packets with the
	//                    flags configured under network.tcp). Equivalent to "raw".
	//   "raw"          — same as legacy default.
	//   "tcp_carrier"  — kernel TCP sockets; bypasses pcap entirely. Same as
	//                    setting TCPCarrier=true.
	//   "handshake_cycle" — per-KCP-packet TCP-handshake mimicry over pcap.
	//                    Each KCP packet rides inside a fresh fake-TCP cycle
	//                    (SYN/SYN-ACK/ACK/PSH-ACK/...). Client rotates source
	//                    ports per cycle so the carrier sees many short
	//                    legit-looking connections rather than one long
	//                    suspicious one.
	//   "handshake_loop" — single long-lived pcap-driven TCP stream, with
	//                    periodic re-handshake mid-stream to reset
	//                    middlebox inspection state.
	Mode string `yaml:"mode"`
	KCP  *KCP   `yaml:"kcp"`
}

func (t *Transport) setDefaults(role string) {
	if t.Conn == 0 {
		t.Conn = 1
	}
	// Map deprecated TCPCarrier bool to the unified Mode field. Mode wins
	// when both are set.
	if t.Mode == "" {
		if t.TCPCarrier {
			t.Mode = "tcp_carrier"
		} else {
			t.Mode = "raw"
		}
	}
	t.TCPCarrier = (t.Mode == "tcp_carrier")

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

	validModes := []string{"raw", "tcp_carrier", "handshake_cycle", "handshake_loop"}
	if !slices.Contains(validModes, t.Mode) {
		errors = append(errors, fmt.Errorf("transport mode must be one of: %v", validModes))
	}

	if t.Conn < 1 || t.Conn > 256 {
		errors = append(errors, fmt.Errorf("KCP conn must be between 1-256 connections"))
	}

	switch t.Protocol {
	case "kcp":
		errors = append(errors, t.KCP.validate()...)
	}

	return errors
}
