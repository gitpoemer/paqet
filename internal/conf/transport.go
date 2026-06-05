package conf

import (
	"fmt"
	"slices"
	"time"
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
	// CycleDataFlag controls which TCP flag combo the server uses when
	// piggybacking KCP data back to the client in handshake_cycle /
	// handshake_loop modes. Some hostile carriers content-sniff inbound
	// packets and silently drop server→client segments based on flag /
	// data combination, while letting other flag combos pass. The
	// observed pattern for the Iranian mobile carrier we tested was:
	// zero-length [S.] and [.] survive, all [P.] with payload dropped.
	// This option lets you try alternative flag combos for the
	// server's data-bearing segments.
	//
	//   "PA" (default) — [PSH-ACK] with payload. Semantically correct,
	//                    widely accepted. Use this on benign paths.
	//   "A"            — bare [ACK] with payload (drop the PSH bit).
	//                    Wire pattern looks like "in-flight data on an
	//                    established flow without urgency hint". Less
	//                    standard but valid TCP.
	//   "SA"           — TCP Fast Open style: server stuffs queued KCP
	//                    data into the SYN-ACK response itself, then
	//                    falls back to bare [ACK] + payload for any
	//                    further in-flow data on the same cycle.
	//   "SAALL"        — like "SA" but EVERY server response (including
	//                    in-flow follow-ups) uses [SYN-ACK] + payload.
	//                    Probes whether the carrier per-flow budget
	//                    re-applies on every SA-flagged packet (each
	//                    SA looks like a fresh handshake completion).
	//                    Highly non-standard TCP; only useful when
	//                    fighting an aggressive content/budget filter.
	CycleDataFlag string `yaml:"cycle_data_flag"`
	// LoopRollInterval — for handshake_loop mode, how long a single flow
	// stays active before being closed and rolled to a new source port.
	// Default 8s. Tune down (e.g. "1s", "500ms") when the carrier filters
	// long-lived flows; tune up when it filters too-many-new-flows. Format:
	// Go's time.ParseDuration ("500ms", "1s", "2s500ms").
	LoopRollInterval_ string        `yaml:"loop_roll_interval"`
	LoopRollInterval  time.Duration `yaml:"-"`
	// CyclePoolSize — for handshake_cycle mode, how many cycles to keep
	// "warm" in a round-robin pool. Default 1 = legacy behaviour (one
	// fresh cycle per KCP packet, max port churn). Set to N>1 to spread
	// KCP packets across N parallel cycles so the carrier sees a handful
	// of medium-lived flows instead of a flood of one-shot ones.
	// Reasonable values: 2-8. Capped at 64.
	CyclePoolSize int `yaml:"cycle_pool_size"`
	// CyclePoolMaxPackets — for handshake_cycle mode, max outbound data
	// packets sent on a single pool cycle before it's retired (FIN'd) and
	// replaced with a fresh handshake. Default 1 = each cycle carries
	// exactly one client→server KCP packet (matches the carrier per-flow
	// budget we observed: ~2 each direction including handshake). Set
	// higher (e.g. 2-4) only if the carrier tolerates more data packets
	// per flow. Capped at 32.
	CyclePoolMaxPackets int  `yaml:"cycle_pool_max_packets"`
	KCP                 *KCP `yaml:"kcp"`
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

	if t.CycleDataFlag == "" {
		t.CycleDataFlag = "PA"
	}
	if t.LoopRollInterval_ == "" {
		t.LoopRollInterval_ = "8s"
	}
	if t.CyclePoolSize == 0 {
		t.CyclePoolSize = 1
	}
	if t.CyclePoolMaxPackets == 0 {
		t.CyclePoolMaxPackets = 1
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

	validDataFlags := []string{"PA", "A", "SA", "SAALL"}
	if !slices.Contains(validDataFlags, t.CycleDataFlag) {
		errors = append(errors, fmt.Errorf("transport cycle_data_flag must be one of: %v", validDataFlags))
	}

	if t.LoopRollInterval_ != "" {
		d, err := time.ParseDuration(t.LoopRollInterval_)
		if err != nil {
			errors = append(errors, fmt.Errorf("transport loop_roll_interval %q: %v", t.LoopRollInterval_, err))
		} else if d < 100*time.Millisecond {
			errors = append(errors, fmt.Errorf("transport loop_roll_interval too small (min 100ms)"))
		} else {
			t.LoopRollInterval = d
		}
	}

	if t.Conn < 1 || t.Conn > 256 {
		errors = append(errors, fmt.Errorf("KCP conn must be between 1-256 connections"))
	}

	if t.CyclePoolSize < 1 || t.CyclePoolSize > 64 {
		errors = append(errors, fmt.Errorf("transport cycle_pool_size must be between 1-64"))
	}
	if t.CyclePoolMaxPackets < 1 || t.CyclePoolMaxPackets > 32 {
		errors = append(errors, fmt.Errorf("transport cycle_pool_max_packets must be between 1-32"))
	}

	switch t.Protocol {
	case "kcp":
		errors = append(errors, t.KCP.validate()...)
	}

	return errors
}
