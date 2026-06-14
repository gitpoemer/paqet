package socks

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

// --- AddrSpec ---

func TestAddrSpec_EncodeDecode_IPv4(t *testing.T) {
	a := AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4(192, 168, 1, 100).To4(), Port: 443}
	if a.EncodedLen() != 7 {
		t.Fatalf("IPv4 EncodedLen = %d want 7", a.EncodedLen())
	}
	dst := make([]byte, a.EncodedLen())
	n := a.Encode(dst)
	if n != 7 {
		t.Fatalf("Encode wrote %d want 7", n)
	}
	want := []byte{ATYPIPv4, 192, 168, 1, 100, 0x01, 0xBB}
	if !bytes.Equal(dst, want) {
		t.Fatalf("wire bytes = % x want % x", dst, want)
	}

	got, err := ReadAddrSpec(bytes.NewReader(dst))
	if err != nil {
		t.Fatal(err)
	}
	if got.ATyp != ATYPIPv4 || !got.IP.Equal(a.IP) || got.Port != 443 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestAddrSpec_EncodeDecode_IPv6(t *testing.T) {
	a := AddrSpec{ATyp: ATYPIPv6, IP: net.ParseIP("2001:db8::1").To16(), Port: 80}
	if a.EncodedLen() != 19 {
		t.Fatalf("IPv6 EncodedLen = %d want 19", a.EncodedLen())
	}
	dst := make([]byte, a.EncodedLen())
	a.Encode(dst)
	got, err := ReadAddrSpec(bytes.NewReader(dst))
	if err != nil {
		t.Fatal(err)
	}
	if got.ATyp != ATYPIPv6 || !got.IP.Equal(a.IP) || got.Port != 80 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestAddrSpec_EncodeDecode_Domain(t *testing.T) {
	a := AddrSpec{ATyp: ATYPDomain, Domain: "example.com", Port: 8443}
	if a.EncodedLen() != 1+1+11+2 {
		t.Fatalf("Domain EncodedLen = %d want 15", a.EncodedLen())
	}
	dst := make([]byte, a.EncodedLen())
	a.Encode(dst)
	got, err := ReadAddrSpec(bytes.NewReader(dst))
	if err != nil {
		t.Fatal(err)
	}
	if got.ATyp != ATYPDomain || got.Domain != "example.com" || got.Port != 8443 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestAddrSpec_MaxLengthDomain(t *testing.T) {
	a := AddrSpec{ATyp: ATYPDomain, Domain: strings.Repeat("a", 255), Port: 1}
	dst := make([]byte, a.EncodedLen())
	a.Encode(dst)
	got, err := ReadAddrSpec(bytes.NewReader(dst))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Domain) != 255 {
		t.Fatalf("got domain len %d want 255", len(got.Domain))
	}
}

func TestReadAddrSpec_ZeroLengthDomain_Rejected(t *testing.T) {
	// ATYP=Domain, len=0, port=0
	buf := []byte{ATYPDomain, 0x00, 0x00, 0x00}
	if _, err := ReadAddrSpec(bytes.NewReader(buf)); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("expected ErrShortFrame, got %v", err)
	}
}

func TestReadAddrSpec_UnsupportedATyp(t *testing.T) {
	// ATYP=0x05 (undefined)
	buf := []byte{0x05}
	if _, err := ReadAddrSpec(bytes.NewReader(buf)); !errors.Is(err, ErrUnsupportedATyp) {
		t.Fatalf("expected ErrUnsupportedATyp, got %v", err)
	}
}

func TestReadAddrSpec_TruncatedIPv4(t *testing.T) {
	// ATYP=IPv4 but only 2 bytes of address
	buf := []byte{ATYPIPv4, 192, 168}
	if _, err := ReadAddrSpec(bytes.NewReader(buf)); err == nil {
		t.Fatal("expected error on truncated IPv4")
	}
}

func TestReadAddrSpec_TruncatedDomain(t *testing.T) {
	// claims 10-byte domain but only provides 5
	buf := []byte{ATYPDomain, 0x0A, 'a', 'b', 'c', 'd', 'e'}
	if _, err := ReadAddrSpec(bytes.NewReader(buf)); err == nil {
		t.Fatal("expected error on truncated domain")
	}
}

func TestReadAddrSpec_MissingPort(t *testing.T) {
	// IPv4 addr complete but no port bytes
	buf := []byte{ATYPIPv4, 1, 2, 3, 4}
	if _, err := ReadAddrSpec(bytes.NewReader(buf)); err == nil {
		t.Fatal("expected error on missing port")
	}
}

// --- Greeting ---

func TestReadGreeting_Valid(t *testing.T) {
	buf := []byte{Version5, 0x02, AuthNoAuth, AuthUserPass}
	g, err := ReadGreeting(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Methods) != 2 || g.Methods[0] != AuthNoAuth || g.Methods[1] != AuthUserPass {
		t.Fatalf("methods mismatch: %v", g.Methods)
	}
}

func TestReadGreeting_BadVersion(t *testing.T) {
	buf := []byte{0x04, 0x01, AuthNoAuth}
	if _, err := ReadGreeting(bytes.NewReader(buf)); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("expected ErrBadVersion, got %v", err)
	}
}

func TestReadGreeting_ZeroMethods(t *testing.T) {
	buf := []byte{Version5, 0x00}
	if _, err := ReadGreeting(bytes.NewReader(buf)); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("expected ErrShortFrame, got %v", err)
	}
}

func TestReadGreeting_MaxMethods(t *testing.T) {
	// NMETHODS=255, all 0x00
	buf := make([]byte, 2+255)
	buf[0] = Version5
	buf[1] = 255
	g, err := ReadGreeting(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if len(g.Methods) != 255 {
		t.Fatalf("expected 255 methods, got %d", len(g.Methods))
	}
}

func TestReadGreeting_TruncatedMethods(t *testing.T) {
	buf := []byte{Version5, 0x03, AuthNoAuth, AuthUserPass} // claims 3, gives 2
	if _, err := ReadGreeting(bytes.NewReader(buf)); err == nil {
		t.Fatal("expected truncated-methods error")
	}
}

func TestReadGreeting_EmptyReader(t *testing.T) {
	if _, err := ReadGreeting(bytes.NewReader(nil)); !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected EOF on empty reader, got %v", err)
	}
}

func TestWriteGreetingResponse(t *testing.T) {
	var w bytes.Buffer
	if err := WriteGreetingResponse(&w, AuthUserPass); err != nil {
		t.Fatal(err)
	}
	want := []byte{Version5, AuthUserPass}
	if !bytes.Equal(w.Bytes(), want) {
		t.Fatalf("wire = % x want % x", w.Bytes(), want)
	}
}

// --- UserPass ---

func TestReadUserPassRequest_Valid(t *testing.T) {
	buf := []byte{UserPassVersion, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'}
	req, err := ReadUserPassRequest(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.Username != "user" || req.Password != "pass" {
		t.Fatalf("got %+v", req)
	}
}

func TestReadUserPassRequest_EmptyPassword(t *testing.T) {
	buf := []byte{UserPassVersion, 0x01, 'x', 0x00}
	req, err := ReadUserPassRequest(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.Username != "x" || req.Password != "" {
		t.Fatalf("got %+v", req)
	}
}

func TestReadUserPassRequest_BadVersion(t *testing.T) {
	buf := []byte{0x02, 0x01, 'x', 0x00}
	if _, err := ReadUserPassRequest(bytes.NewReader(buf)); !errors.Is(err, ErrUserPassBadVer) {
		t.Fatalf("expected ErrUserPassBadVer, got %v", err)
	}
}

func TestReadUserPassRequest_ZeroUlen(t *testing.T) {
	buf := []byte{UserPassVersion, 0x00, 0x01, 'p'}
	if _, err := ReadUserPassRequest(bytes.NewReader(buf)); !errors.Is(err, ErrShortFrame) {
		t.Fatalf("expected ErrShortFrame, got %v", err)
	}
}

func TestReadUserPassRequest_MaxLengths(t *testing.T) {
	uname := strings.Repeat("u", 255)
	passwd := strings.Repeat("p", 255)
	buf := append([]byte{UserPassVersion, 255}, []byte(uname)...)
	buf = append(buf, 255)
	buf = append(buf, []byte(passwd)...)
	req, err := ReadUserPassRequest(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if len(req.Username) != 255 || len(req.Password) != 255 {
		t.Fatalf("max-len lengths wrong: u=%d p=%d", len(req.Username), len(req.Password))
	}
}

func TestReadUserPassRequest_TruncatedPassword(t *testing.T) {
	buf := []byte{UserPassVersion, 0x01, 'x', 0x05, 'a', 'b'} // claims 5-byte password, 2 given
	if _, err := ReadUserPassRequest(bytes.NewReader(buf)); err == nil {
		t.Fatal("expected truncated password error")
	}
}

func TestWriteUserPassResponse_Success(t *testing.T) {
	var w bytes.Buffer
	if err := WriteUserPassResponse(&w, UserPassSuccess); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(w.Bytes(), []byte{UserPassVersion, UserPassSuccess}) {
		t.Fatalf("wire = % x", w.Bytes())
	}
}

// --- Request ---

func TestReadRequest_Connect_IPv4(t *testing.T) {
	buf := []byte{Version5, CmdConnect, 0x00, ATYPIPv4, 8, 8, 8, 8, 0x00, 0x35}
	req, err := ReadRequest(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.Cmd != CmdConnect || req.Dest.Port != 53 || !req.Dest.IP.Equal(net.IPv4(8, 8, 8, 8)) {
		t.Fatalf("got %+v", req)
	}
}

func TestReadRequest_BadVersion(t *testing.T) {
	buf := []byte{0x04, CmdConnect, 0x00, ATYPIPv4, 1, 1, 1, 1, 0x00, 0x50}
	if _, err := ReadRequest(bytes.NewReader(buf)); !errors.Is(err, ErrBadVersion) {
		t.Fatalf("expected ErrBadVersion, got %v", err)
	}
}

func TestReadRequest_UDPAssociate_Domain(t *testing.T) {
	buf := []byte{Version5, CmdUDPAssociate, 0x00, ATYPDomain, 0x03, 'd', 'n', 's', 0x00, 0x35}
	req, err := ReadRequest(bytes.NewReader(buf))
	if err != nil {
		t.Fatal(err)
	}
	if req.Cmd != CmdUDPAssociate || req.Dest.Domain != "dns" || req.Dest.Port != 53 {
		t.Fatalf("got %+v", req)
	}
}

func TestReadRequest_RSV_Ignored(t *testing.T) {
	// RSV = 0xFF should be accepted; we don't validate it
	buf := []byte{Version5, CmdConnect, 0xFF, ATYPIPv4, 1, 1, 1, 1, 0x00, 0x50}
	if _, err := ReadRequest(bytes.NewReader(buf)); err != nil {
		t.Fatalf("RSV should not cause error: %v", err)
	}
}

func TestWriteReply_IPv4(t *testing.T) {
	var w bytes.Buffer
	bnd := AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4(127, 0, 0, 1).To4(), Port: 1080}
	if err := WriteReply(&w, RepSuccess, bnd, nil); err != nil {
		t.Fatal(err)
	}
	want := []byte{Version5, RepSuccess, 0x00, ATYPIPv4, 127, 0, 0, 1, 0x04, 0x38}
	if !bytes.Equal(w.Bytes(), want) {
		t.Fatalf("wire = % x want % x", w.Bytes(), want)
	}
}

func TestWriteReply_ScratchReuse(t *testing.T) {
	// Provide a scratch large enough to avoid alloc; verify the encoder
	// uses it.
	scratch := make([]byte, 64)
	var w bytes.Buffer
	bnd := AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4(10, 0, 0, 1).To4(), Port: 80}
	if err := WriteReply(&w, RepSuccess, bnd, scratch); err != nil {
		t.Fatal(err)
	}
	if w.Len() != 10 {
		t.Fatalf("reply len = %d want 10", w.Len())
	}
}

// --- UDP datagram ---

func TestParseUDPDatagram_Valid_IPv4(t *testing.T) {
	// RSV(2) FRAG(1) ATYP(1) IPv4(4) PORT(2) DATA(5)
	buf := []byte{0, 0, 0, ATYPIPv4, 8, 8, 8, 8, 0x00, 0x35, 'h', 'e', 'l', 'l', 'o'}
	dg, err := ParseUDPDatagram(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !dg.Dest.IP.Equal(net.IPv4(8, 8, 8, 8)) || dg.Dest.Port != 53 || string(dg.Data) != "hello" {
		t.Fatalf("got %+v data=%q", dg, dg.Data)
	}
}

func TestParseUDPDatagram_Valid_IPv6(t *testing.T) {
	addr := net.ParseIP("2001:db8::42").To16()
	buf := []byte{0, 0, 0, ATYPIPv6}
	buf = append(buf, addr...)
	buf = binary.BigEndian.AppendUint16(buf, 443)
	buf = append(buf, []byte("ping")...)
	dg, err := ParseUDPDatagram(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !dg.Dest.IP.Equal(addr) || dg.Dest.Port != 443 || string(dg.Data) != "ping" {
		t.Fatalf("got %+v", dg)
	}
}

func TestParseUDPDatagram_Valid_Domain(t *testing.T) {
	domain := "dns.example"
	buf := []byte{0, 0, 0, ATYPDomain, byte(len(domain))}
	buf = append(buf, []byte(domain)...)
	buf = binary.BigEndian.AppendUint16(buf, 53)
	buf = append(buf, 0xAA, 0xBB)
	dg, err := ParseUDPDatagram(buf)
	if err != nil {
		t.Fatal(err)
	}
	if dg.Dest.Domain != domain || dg.Dest.Port != 53 || !bytes.Equal(dg.Data, []byte{0xAA, 0xBB}) {
		t.Fatalf("got %+v data=% x", dg, dg.Data)
	}
}

func TestParseUDPDatagram_Empty_Rejected(t *testing.T) {
	if _, err := ParseUDPDatagram(nil); !errors.Is(err, ErrUDPHeaderTooShort) {
		t.Fatalf("expected ErrUDPHeaderTooShort, got %v", err)
	}
	if _, err := ParseUDPDatagram([]byte{0, 0, 0}); !errors.Is(err, ErrUDPHeaderTooShort) {
		t.Fatalf("expected ErrUDPHeaderTooShort, got %v", err)
	}
}

func TestParseUDPDatagram_FragmentRejected(t *testing.T) {
	buf := []byte{0, 0, 0x01, ATYPIPv4, 1, 1, 1, 1, 0x00, 0x50}
	if _, err := ParseUDPDatagram(buf); !errors.Is(err, ErrUDPHasFragment) {
		t.Fatalf("expected ErrUDPHasFragment, got %v", err)
	}
}

func TestParseUDPDatagram_UnsupportedATyp(t *testing.T) {
	buf := []byte{0, 0, 0, 0x09, 0, 0, 0, 0}
	if _, err := ParseUDPDatagram(buf); !errors.Is(err, ErrUnsupportedATyp) {
		t.Fatalf("expected ErrUnsupportedATyp, got %v", err)
	}
}

func TestParseUDPDatagram_TruncatedIPv4(t *testing.T) {
	buf := []byte{0, 0, 0, ATYPIPv4, 1, 2, 3} // missing 4th byte + port
	if _, err := ParseUDPDatagram(buf); !errors.Is(err, ErrUDPHeaderTooShort) {
		t.Fatalf("expected ErrUDPHeaderTooShort, got %v", err)
	}
}

func TestParseUDPDatagram_TruncatedDomain(t *testing.T) {
	buf := []byte{0, 0, 0, ATYPDomain, 0x0A, 'a', 'b'} // claims 10, gives 2
	if _, err := ParseUDPDatagram(buf); !errors.Is(err, ErrUDPHeaderTooShort) {
		t.Fatalf("expected ErrUDPHeaderTooShort, got %v", err)
	}
}

func TestParseUDPDatagram_ZeroLengthDomain(t *testing.T) {
	buf := []byte{0, 0, 0, ATYPDomain, 0x00, 0x00, 0x50}
	if _, err := ParseUDPDatagram(buf); !errors.Is(err, ErrUDPHeaderTooShort) {
		t.Fatalf("expected ErrUDPHeaderTooShort, got %v", err)
	}
}

func TestEncodeUDPDatagram_Roundtrip(t *testing.T) {
	dest := AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4(1, 2, 3, 4).To4(), Port: 53}
	payload := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	need := UDPDatagramEncodedLen(dest, len(payload))
	buf := make([]byte, need)
	n := EncodeUDPDatagram(buf, dest, payload)
	if n != need {
		t.Fatalf("encoder wrote %d want %d", n, need)
	}
	dg, err := ParseUDPDatagram(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if !dg.Dest.IP.Equal(dest.IP) || dg.Dest.Port != dest.Port || !bytes.Equal(dg.Data, payload) {
		t.Fatalf("roundtrip mismatch: %+v data=% x", dg, dg.Data)
	}
}

// --- AddrSpec.String ---

func TestAddrSpec_String_IPv4(t *testing.T) {
	a := AddrSpec{ATyp: ATYPIPv4, IP: net.IPv4(127, 0, 0, 1), Port: 80}
	if got := a.String(); got != "127.0.0.1:80" {
		t.Fatalf("got %q", got)
	}
}

func TestAddrSpec_String_IPv6(t *testing.T) {
	a := AddrSpec{ATyp: ATYPIPv6, IP: net.ParseIP("::1"), Port: 80}
	if got := a.String(); got != "[::1]:80" {
		t.Fatalf("got %q", got)
	}
}

func TestAddrSpec_String_Domain(t *testing.T) {
	a := AddrSpec{ATyp: ATYPDomain, Domain: "example.com", Port: 443}
	if got := a.String(); got != "example.com:443" {
		t.Fatalf("got %q", got)
	}
}
