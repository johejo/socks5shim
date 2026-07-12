package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"
)

const (
	socksVersion = 0x05
	socksRSV     = 0x00

	socksMethodNoAuth       = 0x00
	socksMethodUserPass     = 0x02
	socksMethodNoAcceptable = 0xFF

	socksUserPassVersion = 0x01
	socksUserPassSuccess = 0x00

	socksCmdConnect = 0x01

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksRepSucceeded           = 0x00
	socksRepGeneralFailure      = 0x01
	socksRepNetworkUnreachable  = 0x03
	socksRepHostUnreachable     = 0x04
	socksRepConnectionRefused   = 0x05
	socksRepTTLExpired          = 0x06
	socksRepCommandNotSupported = 0x07
	socksRepAddressTypeNotSupp  = 0x08

	socksGreetingHeaderLen = 2
	socksConnectHeaderLen  = 4
	socksIPv4AddrLen       = 4
	socksIPv6AddrLen       = 16
	socksPortLen           = 2
)

var errAddressTypeNotSupported = errors.New("address type not supported")
var errUnknownReplyAddressType = errors.New("unknown reply address type")

// socks5Creds holds RFC 1929 credentials captured from the client,
// forwarded verbatim to the upstream proxy. Never validated locally.
type socks5Creds struct {
	username string
	password string
}

// socks5Target holds the parsed CONNECT request from the client.
type socks5Target struct {
	atyp   byte
	ip     netip.Addr // valid for atyp 0x01, 0x04
	domain string     // valid for atyp 0x03
	port   uint16
	addr   string // host:port for dialing
}

func (p *proxy) handle(client net.Conn) {
	defer client.Close()
	if err := client.SetReadDeadline(time.Now().Add(p.readTimeout())); err != nil {
		return
	}

	// --- SOCKS5 auth negotiation ---
	// Client greeting: VER NMETHODS METHODS...
	hdr := make([]byte, socksGreetingHeaderLen)
	if _, err := io.ReadFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != socksVersion {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}
	// Prefer username/password over no-auth: a client only offers 0x02 when
	// it has credentials, and picking 0x00 would drop them.
	var creds *socks5Creds
	switch {
	case slices.Contains(methods, socksMethodUserPass):
		if _, err := client.Write([]byte{socksVersion, socksMethodUserPass}); err != nil {
			return
		}
		c, err := readUserPassAuth(client)
		if err != nil {
			return
		}
		// Pass-through: always ACK. The upstream is the real validator; its
		// rejection surfaces later as a CONNECT general-failure reply.
		if _, err := client.Write([]byte{socksUserPassVersion, socksUserPassSuccess}); err != nil {
			return
		}
		creds = &c
	case slices.Contains(methods, socksMethodNoAuth):
		if _, err := client.Write([]byte{socksVersion, socksMethodNoAuth}); err != nil {
			return
		}
	default:
		client.Write([]byte{socksVersion, socksMethodNoAcceptable})
		return
	}

	// --- SOCKS5 CONNECT request ---
	req := make([]byte, socksConnectHeaderLen)
	if _, err := io.ReadFull(client, req); err != nil {
		return
	}
	if req[0] != socksVersion || req[2] != socksRSV {
		sendReply(client, socksRepGeneralFailure)
		return
	}
	if req[1] != socksCmdConnect {
		sendReply(client, socksRepCommandNotSupported)
		return
	}

	target, err := readTarget(client, req[3])
	if err != nil {
		if errors.Is(err, errAddressTypeNotSupported) {
			sendReply(client, socksRepAddressTypeNotSupp)
			return
		}
		sendReply(client, socksRepGeneralFailure)
		return
	}
	if err := client.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	// --- Try upstream, fallback to direct ---
	// No cancel source exists on the SOCKS5 path (no graceful shutdown, and
	// watching the client for disconnect would consume bytes an eager client
	// pipelines behind the CONNECT request); dial bounds itself with its own
	// timeouts.
	remote, viaUpstream, err := p.dial(context.Background(), target, creds)
	if err != nil {
		log.Printf("FAIL %s: %v", target.addr, err)
		var upstreamErr upstreamConnectError
		if errors.As(err, &upstreamErr) {
			sendReply(client, upstreamErr.rep)
			return
		}
		if errors.Is(err, errUpstreamProtocol) || errors.Is(err, errUpstreamAuth) {
			sendReply(client, socksRepGeneralFailure)
			return
		}
		sendReply(client, replyCodeFromDialError(err))
		return
	}
	defer remote.Close()

	if viaUpstream {
		log.Printf("PROXY %s", target.addr)
	} else {
		log.Printf("DIRECT %s -> %s", target.addr, remote.RemoteAddr())
	}
	sendReplyWithBind(client, socksRepSucceeded, remote.LocalAddr())
	relay(client, remote)
}

// readUserPassAuth parses the RFC 1929 subnegotiation:
// VER(0x01) ULEN UNAME[ULEN] PLEN PASSWD[PLEN].
// Zero-length fields are accepted (the RFC says 1-255, but the shim is a
// pass-through and leaves validation to the upstream).
func readUserPassAuth(r io.Reader) (socks5Creds, error) {
	var c socks5Creds

	hdr := make([]byte, 2) // VER ULEN
	if _, err := io.ReadFull(r, hdr); err != nil {
		return c, err
	}
	if hdr[0] != socksUserPassVersion {
		return c, fmt.Errorf("unsupported auth subnegotiation version: %d", hdr[0])
	}
	uname := make([]byte, int(hdr[1])+1) // UNAME plus the trailing PLEN byte
	if _, err := io.ReadFull(r, uname); err != nil {
		return c, err
	}
	c.username = string(uname[:hdr[1]])
	plen := uname[hdr[1]]
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(r, passwd); err != nil {
		return c, err
	}
	c.password = string(passwd)
	return c, nil
}

// readTarget parses the destination address from a SOCKS5 CONNECT request.
func readTarget(r io.Reader, atyp byte) (socks5Target, error) {
	var t socks5Target
	t.atyp = atyp

	switch atyp {
	case socksAtypIPv4:
		buf := make([]byte, socksIPv4AddrLen+socksPortLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return t, err
		}
		t.ip = netip.AddrFrom4([socksIPv4AddrLen]byte(buf[:socksIPv4AddrLen]))
		t.port = binary.BigEndian.Uint16(buf[socksIPv4AddrLen : socksIPv4AddrLen+socksPortLen])

	case socksAtypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return t, err
		}
		if lenBuf[0] == 0 {
			return t, fmt.Errorf("empty domain")
		}
		buf := make([]byte, int(lenBuf[0])+socksPortLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return t, err
		}
		t.domain = string(buf[:lenBuf[0]])
		t.port = binary.BigEndian.Uint16(buf[lenBuf[0]:])

	case socksAtypIPv6:
		buf := make([]byte, socksIPv6AddrLen+socksPortLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return t, err
		}
		t.ip = netip.AddrFrom16([socksIPv6AddrLen]byte(buf[:socksIPv6AddrLen]))
		t.port = binary.BigEndian.Uint16(buf[socksIPv6AddrLen : socksIPv6AddrLen+socksPortLen])

	default:
		return t, fmt.Errorf("%w: %d", errAddressTypeNotSupported, atyp)
	}

	if atyp == socksAtypDomain {
		t.addr = net.JoinHostPort(t.domain, strconv.Itoa(int(t.port)))
	} else {
		t.addr = netip.AddrPortFrom(t.ip, t.port).String()
	}
	return t, nil
}

// dialUpstream performs a full SOCKS5 handshake with the upstream proxy.
// p.dialTimeout covers TCP connect + greeting; p.connectTimeout covers the
// CONNECT request/reply (includes the upstream-side dial to the target).
// It deliberately takes no ctx; dial handles cancellation (see its doc).
func (p *proxy) dialUpstream(target socks5Target, creds *socks5Creds) (net.Conn, error) {
	helloTimeout := p.dialTimeout
	if helloTimeout <= 0 {
		helloTimeout = defaultUpstreamDialTimeout
	}
	connectTimeout := p.connectTimeout
	if connectTimeout <= 0 {
		connectTimeout = defaultUpstreamConnectTimeout
	}
	conn, err := net.DialTimeout("tcp", p.upstream, helloTimeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(helloTimeout)); err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}

	// Greeting: offer username/password too when the client supplied
	// credentials to pass through.
	greeting := []byte{socksVersion, 0x01, socksMethodNoAuth}
	if creds != nil {
		greeting = []byte{socksVersion, 0x02, socksMethodNoAuth, socksMethodUserPass}
	}
	if _, err := conn.Write(greeting); err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}
	resp := make([]byte, socksGreetingHeaderLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}
	switch {
	case resp[0] != socksVersion:
		return nil, fmt.Errorf("%w: auth response %x %x", errUpstreamProtocol, resp[0], resp[1])
	case resp[1] == socksMethodNoAuth:
	case resp[1] == socksMethodUserPass && creds != nil:
		// Credential verification may wait on a slow upstream auth backend
		// (LDAP/RADIUS), so give it the connect budget rather than the short
		// greeting one.
		if err := conn.SetDeadline(time.Now().Add(connectTimeout)); err != nil {
			return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
		}
		if err := authUpstream(conn, creds); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: auth response %x %x", errUpstreamProtocol, resp[0], resp[1])
	}

	// The CONNECT reply waits on the upstream-side dial, so it gets its own deadline.
	if err := conn.SetDeadline(time.Now().Add(connectTimeout)); err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}

	// CONNECT request
	if _, err := conn.Write(buildConnectRequest(target)); err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}

	reply := make([]byte, socksConnectHeaderLen)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}
	if reply[0] != socksVersion || reply[2] != socksRSV {
		return nil, fmt.Errorf("%w: reply header ver=0x%02x rsv=0x%02x", errUpstreamProtocol, reply[0], reply[2])
	}
	if reply[1] != socksRepSucceeded {
		return nil, upstreamConnectError{rep: reply[1]}
	}
	if err := drainBoundAddr(conn, reply[3]); err != nil {
		if errors.Is(err, errUnknownReplyAddressType) {
			return nil, fmt.Errorf("%w: %v", errUpstreamProtocol, err)
		}
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}

	conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
}

// authUpstream performs the RFC 1929 subnegotiation with the upstream.
// Failures here are auth failures, never unavailability: some servers reject
// bad credentials by closing mid-subnegotiation instead of sending a STATUS
// byte, and treating that as unavailability would bypass the rejection via a
// credential-less direct fallback. This path is deliberately fail-closed.
func authUpstream(conn net.Conn, creds *socks5Creds) error {
	if _, err := conn.Write(buildUserPassRequest(creds)); err != nil {
		return fmt.Errorf("%w: %v", errUpstreamAuth, err)
	}
	reply := make([]byte, 2) // VER STATUS
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("%w: %v", errUpstreamAuth, err)
	}
	if reply[0] != socksUserPassVersion {
		return fmt.Errorf("%w: auth reply version 0x%02x", errUpstreamProtocol, reply[0])
	}
	if reply[1] != socksUserPassSuccess {
		return fmt.Errorf("%w: status=0x%02x", errUpstreamAuth, reply[1])
	}
	return nil
}

func buildUserPassRequest(c *socks5Creds) []byte {
	buf := []byte{socksUserPassVersion, byte(len(c.username))}
	buf = append(buf, c.username...)
	buf = append(buf, byte(len(c.password)))
	return append(buf, c.password...)
}

func buildConnectRequest(t socks5Target) []byte {
	buf := []byte{socksVersion, socksCmdConnect, socksRSV, t.atyp}
	switch t.atyp {
	case socksAtypIPv4:
		a4 := t.ip.As4()
		buf = append(buf, a4[:]...)
	case socksAtypDomain:
		buf = append(buf, byte(len(t.domain)))
		buf = append(buf, t.domain...)
	case socksAtypIPv6:
		a16 := t.ip.As16()
		buf = append(buf, a16[:]...)
	}
	return binary.BigEndian.AppendUint16(buf, t.port)
}

func drainBoundAddr(r io.Reader, atyp byte) error {
	switch atyp {
	case socksAtypIPv4:
		return discardN(r, socksIPv4AddrLen+socksPortLen)
	case socksAtypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return err
		}
		return discardN(r, int(lb[0])+socksPortLen)
	case socksAtypIPv6:
		return discardN(r, socksIPv6AddrLen+socksPortLen)
	default:
		return fmt.Errorf("%w: %d", errUnknownReplyAddressType, atyp)
	}
}

func discardN(r io.Reader, n int) error {
	if n <= 0 {
		return nil
	}
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}

func sendReply(w io.Writer, rep byte) {
	sendReplyWithBind(w, rep, nil)
}

func sendReplyWithBind(w io.Writer, rep byte, bind net.Addr) {
	if rep != socksRepSucceeded {
		w.Write([]byte{socksVersion, rep, socksRSV, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	tcpAddr, ok := bind.(*net.TCPAddr)
	if !ok || tcpAddr == nil || tcpAddr.IP == nil {
		w.Write([]byte{socksVersion, rep, socksRSV, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}

	if ip4 := tcpAddr.IP.To4(); ip4 != nil {
		msg := make([]byte, 0, 4+socksIPv4AddrLen+socksPortLen)
		msg = append(msg, socksVersion, rep, socksRSV, socksAtypIPv4)
		msg = append(msg, ip4...)
		msg = binary.BigEndian.AppendUint16(msg, uint16(tcpAddr.Port))
		w.Write(msg)
		return
	}

	if ip16 := tcpAddr.IP.To16(); ip16 != nil {
		msg := make([]byte, 0, 4+socksIPv6AddrLen+socksPortLen)
		msg = append(msg, socksVersion, rep, socksRSV, socksAtypIPv6)
		msg = append(msg, ip16...)
		msg = binary.BigEndian.AppendUint16(msg, uint16(tcpAddr.Port))
		w.Write(msg)
		return
	}

	w.Write([]byte{socksVersion, rep, socksRSV, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
}
