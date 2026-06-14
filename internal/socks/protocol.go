package socks

// SOCKS5 wire format primitives. RFC 1928 + RFC 1929 (user/pass auth).
//
// This file is the entire on-wire layer: constants, address-spec
// codec, greeting / auth / request / reply / UDP-datagram readers
// and writers. Higher layers (server.go, udp_assoc.go) use these
// without ever touching raw bytes themselves.
//
// Design notes:
//   - All readers take an io.Reader and use io.ReadFull so partial-
//     read failures surface as errors, not as silently-truncated
//     frames. The standard library does NOT guarantee Read fills a
//     buffer; everything multi-byte goes through io.ReadFull.
//   - Writers take a byte slice the caller pre-sized via
//     EncodedLen-style helpers. No allocations on the hot path.
//   - Domain names are length-prefixed (1 byte, 0-255). Anything
//     longer is a protocol violation, rejected.
//   - All errors are sentinel errors so callers can switch on them
//     to select the SOCKS5 reply code that goes back to the client.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// Protocol version and constant bytes.
const (
	Version5 byte = 5

	// Auth methods (greeting METHODS / response METHOD).
	AuthNoAuth         byte = 0x00
	AuthGSSAPI         byte = 0x01
	AuthUserPass       byte = 0x02
	AuthNoneAcceptable byte = 0xFF

	// User/Pass sub-negotiation (RFC 1929).
	UserPassVersion byte = 0x01
	UserPassSuccess byte = 0x00
	UserPassFailure byte = 0x01

	// Command codes.
	CmdConnect      byte = 0x01
	CmdBind         byte = 0x02
	CmdUDPAssociate byte = 0x03

	// Address types.
	ATYPIPv4   byte = 0x01
	ATYPDomain byte = 0x03
	ATYPIPv6   byte = 0x04

	// Reply codes.
	RepSuccess           byte = 0x00
	RepGeneralFailure    byte = 0x01
	RepConnNotAllowed    byte = 0x02
	RepNetworkUnreach    byte = 0x03
	RepHostUnreach       byte = 0x04
	RepConnRefused       byte = 0x05
	RepTTLExpired        byte = 0x06
	RepCmdNotSupported   byte = 0x07
	RepATypeNotSupported byte = 0x08
)

// Limits.
const (
	// MaxDomainLen is the largest ATYPDomain we accept. RFC 1928 says
	// the domain length byte is 1-255, and 253 is the practical DNS
	// limit; we accept up to 255 to be permissive.
	MaxDomainLen = 255

	// MaxUserPassFieldLen is the largest ULEN or PLEN we accept per
	// RFC 1929 (single byte → 255).
	MaxUserPassFieldLen = 255

	// MaxGreetingMethods is the largest NMETHODS we accept. RFC 1928
	// uses one byte for the count, so 255 is the cap.
	MaxGreetingMethods = 255
)

// Sentinel errors. Each maps to one SOCKS5 reply code.
var (
	ErrBadVersion        = errors.New("socks5: wrong VER byte")
	ErrUnsupportedAuth   = errors.New("socks5: no acceptable auth method")
	ErrAuthFailed        = errors.New("socks5: username/password rejected")
	ErrUnsupportedCmd    = errors.New("socks5: command not supported")
	ErrUnsupportedATyp   = errors.New("socks5: address type not supported")
	ErrShortFrame        = errors.New("socks5: truncated frame")
	ErrDomainTooLong     = errors.New("socks5: domain name exceeds 255 bytes")
	ErrUserPassBadVer    = errors.New("socks5: user/pass auth wrong version")
	ErrUDPHeaderTooShort = errors.New("socks5: UDP datagram header too short")
	ErrUDPHasFragment    = errors.New("socks5: UDP datagram fragmentation not supported")
)

// AddrSpec carries a SOCKS5 address-type + address + port tuple. Exactly
// one of IP / Domain is populated based on ATyp.
type AddrSpec struct {
	ATyp   byte
	IP     net.IP // length is 4 for IPv4 or 16 for IPv6; nil if ATyp == ATYPDomain
	Domain string // populated if ATyp == ATYPDomain
	Port   uint16
}

// String returns "host:port" suitable for net.Dial. Domain wins over
// IP when ATyp is Domain (preserves DNS resolution).
func (a AddrSpec) String() string {
	host := a.Domain
	if host == "" && a.IP != nil {
		host = a.IP.String()
	}
	return net.JoinHostPort(host, fmt.Sprintf("%d", a.Port))
}

// EncodedLen returns the on-wire size of this AddrSpec
// (atyp + addr + 2-byte port).
func (a AddrSpec) EncodedLen() int {
	switch a.ATyp {
	case ATYPIPv4:
		return 1 + 4 + 2
	case ATYPIPv6:
		return 1 + 16 + 2
	case ATYPDomain:
		return 1 + 1 + len(a.Domain) + 2
	}
	return 0
}

// Encode writes the on-wire representation into dst, returning the
// number of bytes written. dst must be at least EncodedLen long.
func (a AddrSpec) Encode(dst []byte) int {
	dst[0] = a.ATyp
	n := 1
	switch a.ATyp {
	case ATYPIPv4:
		ip4 := a.IP.To4()
		copy(dst[n:n+4], ip4)
		n += 4
	case ATYPIPv6:
		ip6 := a.IP.To16()
		copy(dst[n:n+16], ip6)
		n += 16
	case ATYPDomain:
		dst[n] = byte(len(a.Domain))
		n++
		copy(dst[n:n+len(a.Domain)], a.Domain)
		n += len(a.Domain)
	}
	binary.BigEndian.PutUint16(dst[n:n+2], a.Port)
	return n + 2
}

// ReadAddrSpec reads ATYP + ADDR + PORT from r and returns the parsed
// AddrSpec. The caller must have already consumed the bytes before the
// ATYP (e.g. VER/CMD/RSV for a Request).
func ReadAddrSpec(r io.Reader) (AddrSpec, error) {
	var buf [1]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return AddrSpec{}, fmt.Errorf("read ATYP: %w", err)
	}
	atyp := buf[0]
	addr := AddrSpec{ATyp: atyp}
	switch atyp {
	case ATYPIPv4:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return AddrSpec{}, fmt.Errorf("read IPv4: %w", err)
		}
		addr.IP = net.IP(append([]byte(nil), b[:]...))
	case ATYPIPv6:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return AddrSpec{}, fmt.Errorf("read IPv6: %w", err)
		}
		addr.IP = net.IP(append([]byte(nil), b[:]...))
	case ATYPDomain:
		var lb [1]byte
		if _, err := io.ReadFull(r, lb[:]); err != nil {
			return AddrSpec{}, fmt.Errorf("read domain len: %w", err)
		}
		dlen := int(lb[0])
		if dlen == 0 {
			return AddrSpec{}, fmt.Errorf("%w: zero-length domain", ErrShortFrame)
		}
		db := make([]byte, dlen)
		if _, err := io.ReadFull(r, db); err != nil {
			return AddrSpec{}, fmt.Errorf("read domain: %w", err)
		}
		addr.Domain = string(db)
	default:
		return AddrSpec{}, ErrUnsupportedATyp
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return AddrSpec{}, fmt.Errorf("read port: %w", err)
	}
	addr.Port = binary.BigEndian.Uint16(pb[:])
	return addr, nil
}

// Greeting is the first client message: VER NMETHODS METHODS[NMETHODS].
type Greeting struct {
	Methods []byte
}

// ReadGreeting parses the client greeting. Caller must NOT have
// consumed the VER byte.
func ReadGreeting(r io.Reader) (Greeting, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Greeting{}, fmt.Errorf("read greeting header: %w", err)
	}
	if hdr[0] != Version5 {
		return Greeting{}, ErrBadVersion
	}
	n := int(hdr[1])
	if n == 0 {
		return Greeting{}, fmt.Errorf("%w: NMETHODS=0", ErrShortFrame)
	}
	methods := make([]byte, n)
	if _, err := io.ReadFull(r, methods); err != nil {
		return Greeting{}, fmt.Errorf("read methods: %w", err)
	}
	return Greeting{Methods: methods}, nil
}

// WriteGreetingResponse writes VER METHOD to w.
func WriteGreetingResponse(w io.Writer, method byte) error {
	_, err := w.Write([]byte{Version5, method})
	return err
}

// UserPassRequest is the user/pass sub-negotiation request: VER ULEN
// UNAME PLEN PASSWD.
type UserPassRequest struct {
	Username string
	Password string
}

// ReadUserPassRequest parses the user/pass auth submission. Caller
// must NOT have consumed the VER byte.
func ReadUserPassRequest(r io.Reader) (UserPassRequest, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return UserPassRequest{}, fmt.Errorf("read userpass header: %w", err)
	}
	if hdr[0] != UserPassVersion {
		return UserPassRequest{}, ErrUserPassBadVer
	}
	ulen := int(hdr[1])
	if ulen == 0 {
		return UserPassRequest{}, fmt.Errorf("%w: zero-length username", ErrShortFrame)
	}
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(r, uname); err != nil {
		return UserPassRequest{}, fmt.Errorf("read username: %w", err)
	}
	var pl [1]byte
	if _, err := io.ReadFull(r, pl[:]); err != nil {
		return UserPassRequest{}, fmt.Errorf("read password len: %w", err)
	}
	plen := int(pl[0])
	passwd := make([]byte, plen)
	if plen > 0 {
		if _, err := io.ReadFull(r, passwd); err != nil {
			return UserPassRequest{}, fmt.Errorf("read password: %w", err)
		}
	}
	return UserPassRequest{Username: string(uname), Password: string(passwd)}, nil
}

// WriteUserPassResponse writes VER STATUS.
func WriteUserPassResponse(w io.Writer, status byte) error {
	_, err := w.Write([]byte{UserPassVersion, status})
	return err
}

// Request is a SOCKS5 request: VER CMD RSV ATYP DST.ADDR DST.PORT.
type Request struct {
	Cmd  byte
	Dest AddrSpec
}

// ReadRequest parses a client request after the auth phase.
func ReadRequest(r io.Reader) (Request, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Request{}, fmt.Errorf("read request header: %w", err)
	}
	if hdr[0] != Version5 {
		return Request{}, ErrBadVersion
	}
	cmd := hdr[1]
	// hdr[2] = RSV, ignored
	dest, err := ReadAddrSpec(r)
	if err != nil {
		return Request{}, fmt.Errorf("request dest: %w", err)
	}
	return Request{Cmd: cmd, Dest: dest}, nil
}

// WriteReply writes VER REP RSV ATYP BND.ADDR BND.PORT. The bound
// address tells the client where the server allocated a UDP relay
// (for UDP_ASSOCIATE) or which interface accepted the TCP connection
// (for CONNECT, where the value is often ignored by clients).
//
// scratch is a caller-provided scratch buffer; if nil, a fresh one is
// allocated. Callers on the hot path should reuse a per-conn scratch
// to avoid per-reply allocations.
func WriteReply(w io.Writer, rep byte, bound AddrSpec, scratch []byte) error {
	need := 3 + bound.EncodedLen()
	if cap(scratch) < need {
		scratch = make([]byte, need)
	} else {
		scratch = scratch[:need]
	}
	scratch[0] = Version5
	scratch[1] = rep
	scratch[2] = 0 // RSV
	bound.Encode(scratch[3:])
	_, err := w.Write(scratch)
	return err
}

// AddrSpecFromTCP returns an AddrSpec describing the given TCP address,
// auto-selecting IPv4 vs IPv6 ATYP based on the IP shape. Used to
// generate BND.ADDR for CONNECT / UDP_ASSOCIATE replies.
func AddrSpecFromTCP(a *net.TCPAddr) AddrSpec {
	if a == nil {
		return AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4zero, Port: 0}
	}
	if ip4 := a.IP.To4(); ip4 != nil {
		return AddrSpec{ATyp: ATYPIPv4, IP: ip4, Port: uint16(a.Port)}
	}
	return AddrSpec{ATyp: ATYPIPv6, IP: a.IP.To16(), Port: uint16(a.Port)}
}

// AddrSpecFromUDP returns an AddrSpec describing the given UDP address.
func AddrSpecFromUDP(a *net.UDPAddr) AddrSpec {
	if a == nil {
		return AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4zero, Port: 0}
	}
	if ip4 := a.IP.To4(); ip4 != nil {
		return AddrSpec{ATyp: ATYPIPv4, IP: ip4, Port: uint16(a.Port)}
	}
	return AddrSpec{ATyp: ATYPIPv6, IP: a.IP.To16(), Port: uint16(a.Port)}
}

// UDPDatagram is a SOCKS5 UDP relay datagram:
//
//	RSV(2) FRAG(1) ATYP(1) DST.ADDR DST.PORT DATA
//
// FRAG != 0 indicates fragmentation; we don't support it and reject
// such datagrams.
type UDPDatagram struct {
	Dest AddrSpec
	Data []byte // slice into the caller-provided buffer
}

// ParseUDPDatagram decodes a SOCKS5 UDP relay datagram from buf in
// place. The returned Data is a slice into buf — do NOT retain past
// the next read into buf.
func ParseUDPDatagram(buf []byte) (UDPDatagram, error) {
	if len(buf) < 4 {
		return UDPDatagram{}, ErrUDPHeaderTooShort
	}
	if buf[2] != 0 {
		return UDPDatagram{}, ErrUDPHasFragment
	}
	atyp := buf[3]
	pos := 4
	dest := AddrSpec{ATyp: atyp}
	switch atyp {
	case ATYPIPv4:
		if len(buf) < pos+4+2 {
			return UDPDatagram{}, ErrUDPHeaderTooShort
		}
		dest.IP = net.IP(append([]byte(nil), buf[pos:pos+4]...))
		pos += 4
	case ATYPIPv6:
		if len(buf) < pos+16+2 {
			return UDPDatagram{}, ErrUDPHeaderTooShort
		}
		dest.IP = net.IP(append([]byte(nil), buf[pos:pos+16]...))
		pos += 16
	case ATYPDomain:
		if len(buf) < pos+1 {
			return UDPDatagram{}, ErrUDPHeaderTooShort
		}
		dlen := int(buf[pos])
		pos++
		if dlen == 0 || len(buf) < pos+dlen+2 {
			return UDPDatagram{}, ErrUDPHeaderTooShort
		}
		dest.Domain = string(buf[pos : pos+dlen])
		pos += dlen
	default:
		return UDPDatagram{}, ErrUnsupportedATyp
	}
	dest.Port = binary.BigEndian.Uint16(buf[pos : pos+2])
	pos += 2
	return UDPDatagram{Dest: dest, Data: buf[pos:]}, nil
}

// UDPDatagramEncodedLen returns the on-wire size of a UDP datagram
// with the given destination spec and payload length.
func UDPDatagramEncodedLen(dest AddrSpec, payloadLen int) int {
	return 2 + 1 + dest.EncodedLen() + payloadLen
}

// EncodeUDPDatagram writes the SOCKS5 UDP relay header followed by
// payload into dst. dst must be at least UDPDatagramEncodedLen.
// Returns the number of bytes written.
func EncodeUDPDatagram(dst []byte, dest AddrSpec, payload []byte) int {
	dst[0] = 0 // RSV
	dst[1] = 0
	dst[2] = 0 // FRAG
	n := 3
	n += dest.Encode(dst[n:])
	copy(dst[n:], payload)
	return n + len(payload)
}
