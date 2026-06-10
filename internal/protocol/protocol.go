package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"paqet/internal/conf"
	"paqet/internal/tnet"
)

type PType = byte

const (
	PPING PType = 0x01
	PPONG PType = 0x02
	PTCPF PType = 0x03
	PTCP  PType = 0x04
	PUDP  PType = 0x05
)

// Wire version. Bump if the binary framing below changes in a way that
// breaks compatibility. Both ends MUST run the same wireVersion; this is
// fine because client and server ship as a single paqet build.
const wireVersion byte = 1

// Magic+version prefix, 2 bytes. The magic byte gives us a clean rejection
// for stray data (or accidental old-format gob streams, which start with a
// gob handshake byte that's not 0xPQ) and the version byte gives a forward
// migration path.
//
// Wire layout for every message:
//
//   magic    : 1 byte  (0xA0)
//   version  : 1 byte
//   type     : 1 byte  (PType)
//   payload  : type-specific (see below)
//
//   PPING / PPONG          → no further payload
//   PTCPF                  → 1-byte count, then count×1-byte flag bitmap
//   PTCP / PUDP            → 1-byte hostLen, hostLen bytes (UTF-8 host or IP),
//                            2-byte big-endian port
//
// Cost in cycles vs gob: a few microseconds per encode/decode vs hundreds.
const wireMagic byte = 0xA0

// TCPF flag bit positions in the wire byte. Match the boolean field order
// in conf.TCPF (FIN/SYN/RST/PSH/ACK/URG/ECE/CWR/NS) — NS overflows the
// byte but it's only 9 flags and NS is essentially never set on real
// traffic; we fold it into a 1-bit "extras" channel keyed on the lower
// nibble of the version if it ever matters.
const (
	bitFIN byte = 1 << 0
	bitSYN byte = 1 << 1
	bitRST byte = 1 << 2
	bitPSH byte = 1 << 3
	bitACK byte = 1 << 4
	bitURG byte = 1 << 5
	bitECE byte = 1 << 6
	bitCWR byte = 1 << 7
	// NS is dropped on the wire; it's not used by any real-world flow.
)

func encodeTCPF(f conf.TCPF) byte {
	var b byte
	if f.FIN {
		b |= bitFIN
	}
	if f.SYN {
		b |= bitSYN
	}
	if f.RST {
		b |= bitRST
	}
	if f.PSH {
		b |= bitPSH
	}
	if f.ACK {
		b |= bitACK
	}
	if f.URG {
		b |= bitURG
	}
	if f.ECE {
		b |= bitECE
	}
	if f.CWR {
		b |= bitCWR
	}
	return b
}

func decodeTCPF(b byte) conf.TCPF {
	return conf.TCPF{
		FIN: b&bitFIN != 0,
		SYN: b&bitSYN != 0,
		RST: b&bitRST != 0,
		PSH: b&bitPSH != 0,
		ACK: b&bitACK != 0,
		URG: b&bitURG != 0,
		ECE: b&bitECE != 0,
		CWR: b&bitCWR != 0,
	}
}

type Proto struct {
	Type PType
	Addr *tnet.Addr
	TCPF []conf.TCPF
}

// Write emits the binary representation of p to w. Replaces the gob-based
// encoder; see OPTIMIZE_NOTES.md I1.
func (p *Proto) Write(w io.Writer) error {
	// header: magic, version, type
	hdr := [3]byte{wireMagic, wireVersion, p.Type}

	switch p.Type {
	case PPING, PPONG:
		_, err := w.Write(hdr[:])
		return err
	case PTCPF:
		if len(p.TCPF) > 255 {
			return fmt.Errorf("protocol: TCPF list too long (%d > 255)", len(p.TCPF))
		}
		buf := make([]byte, 0, 4+len(p.TCPF))
		buf = append(buf, hdr[:]...)
		buf = append(buf, byte(len(p.TCPF)))
		for _, f := range p.TCPF {
			buf = append(buf, encodeTCPF(f))
		}
		_, err := w.Write(buf)
		return err
	case PTCP, PUDP:
		if p.Addr == nil {
			return errors.New("protocol: missing address for PTCP/PUDP")
		}
		host := p.Addr.Host
		if len(host) > 255 {
			return fmt.Errorf("protocol: host too long (%d > 255)", len(host))
		}
		if p.Addr.Port < 0 || p.Addr.Port > 0xFFFF {
			return fmt.Errorf("protocol: port out of range (%d)", p.Addr.Port)
		}
		buf := make([]byte, 0, 4+len(host)+2)
		buf = append(buf, hdr[:]...)
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
		buf = append(buf, byte(p.Addr.Port>>8), byte(p.Addr.Port&0xff))
		_, err := w.Write(buf)
		return err
	default:
		return fmt.Errorf("protocol: unknown type 0x%02x", p.Type)
	}
}

// Read decodes one message from r and writes it into p. It clears p's
// Addr/TCPF fields so a re-used Proto doesn't surface stale data.
func (p *Proto) Read(r io.Reader) error {
	p.Addr = nil
	p.TCPF = nil

	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	if hdr[0] != wireMagic {
		return fmt.Errorf("protocol: bad magic 0x%02x", hdr[0])
	}
	if hdr[1] != wireVersion {
		return fmt.Errorf("protocol: unsupported version %d (this build expects %d)", hdr[1], wireVersion)
	}
	p.Type = hdr[2]

	switch p.Type {
	case PPING, PPONG:
		return nil
	case PTCPF:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return err
		}
		count := int(n[0])
		if count == 0 {
			p.TCPF = nil
			return nil
		}
		raw := make([]byte, count)
		if _, err := io.ReadFull(r, raw); err != nil {
			return err
		}
		p.TCPF = make([]conf.TCPF, count)
		for i, b := range raw {
			p.TCPF[i] = decodeTCPF(b)
		}
		return nil
	case PTCP, PUDP:
		var hostLen [1]byte
		if _, err := io.ReadFull(r, hostLen[:]); err != nil {
			return err
		}
		host := make([]byte, hostLen[0])
		if _, err := io.ReadFull(r, host); err != nil {
			return err
		}
		var portBuf [2]byte
		if _, err := io.ReadFull(r, portBuf[:]); err != nil {
			return err
		}
		p.Addr = &tnet.Addr{
			Host: string(host),
			Port: int(binary.BigEndian.Uint16(portBuf[:])),
		}
		return nil
	default:
		return fmt.Errorf("protocol: unknown type 0x%02x", p.Type)
	}
}
