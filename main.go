package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"runtime/debug"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	socksVersion = 0x05
	socksRSV     = 0x00

	socksMethodNoAuth         = 0x00
	socksMethodNoAcceptable   = 0xFF
	socksMethodSelectionCount = 0x01

	socksCmdConnect = 0x01

	socksAtypIPv4   = 0x01
	socksAtypDomain = 0x03
	socksAtypIPv6   = 0x04

	socksRepSucceeded           = 0x00
	socksRepGeneralFailure      = 0x01
	socksRepNetworkUnreachable  = 0x03
	socksRepHostUnreachable     = 0x04
	socksRepConnectionRefused   = 0x05
	socksRepCommandNotSupported = 0x07
	socksRepAddressTypeNotSupp  = 0x08

	socksGreetingHeaderLen = 2
	socksConnectHeaderLen  = 4
	socksIPv4AddrLen       = 4
	socksIPv6AddrLen       = 16
	socksPortLen           = 2

	defaultUpstreamDialTimeout = 2 * time.Second
	defaultClientReadTimeout   = 5 * time.Second
	directDialTimeout          = 10 * time.Second
	upstreamUnavailableBackoff = 3 * time.Second
)

var errAddressTypeNotSupported = errors.New("address type not supported")
var errUpstreamUnavailable = errors.New("upstream unavailable")
var errUpstreamProtocol = errors.New("upstream protocol error")
var errUnknownReplyAddressType = errors.New("unknown reply address type")

var upstreamBackoffCache = newUpstreamBackoffState(upstreamUnavailableBackoff)
var version string

type upstreamConnectError struct {
	rep byte
}

func (e upstreamConnectError) Error() string {
	return fmt.Sprintf("upstream CONNECT failed: rep=0x%02x", e.rep)
}

type upstreamBackoffState struct {
	mu       sync.Mutex
	until    map[string]time.Time
	duration time.Duration
}

func newUpstreamBackoffState(duration time.Duration) *upstreamBackoffState {
	return &upstreamBackoffState{
		until:    map[string]time.Time{},
		duration: duration,
	}
}

func (s *upstreamBackoffState) shouldSkip(addr string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	until, ok := s.until[addr]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(s.until, addr)
		return false
	}
	return true
}

func (s *upstreamBackoffState) markUnavailable(addr string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.until[addr] = now.Add(s.duration)
}

func (s *upstreamBackoffState) clear(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.until, addr)
}

func main() {
	listen := flag.String("listen", "127.0.0.1:1081", "listen address")
	upstream := flag.String("upstream", "127.0.0.1:1080", "upstream SOCKS5 proxy address")
	dialTimeout := flag.Duration("dial-timeout", defaultUpstreamDialTimeout, "timeout for connecting to upstream")
	clientReadTimeout := flag.Duration("client-handshake-timeout", defaultClientReadTimeout, "timeout for reading SOCKS5 greeting/request from client")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(resolveVersion())
		return
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s, upstream %s (timeout %s)", *listen, *upstream, *dialTimeout)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handle(conn, *upstream, *dialTimeout, *clientReadTimeout)
	}
}

func resolveVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if ok && info != nil && info.Main.Version != "" {
		return info.Main.Version
	}
	return ""
}

// socks5Target holds the parsed CONNECT request from the client.
type socks5Target struct {
	atyp   byte
	ip     netip.Addr // valid for atyp 0x01, 0x04
	domain string     // valid for atyp 0x03
	port   uint16
	addr   string // host:port for dialing
}

func handle(client net.Conn, upstream string, dialTimeout, clientReadTimeout time.Duration) {
	defer client.Close()
	if clientReadTimeout <= 0 {
		clientReadTimeout = defaultClientReadTimeout
	}
	if err := client.SetReadDeadline(time.Now().Add(clientReadTimeout)); err != nil {
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
	// Select "no authentication required" only if the client offered it.
	if !slices.Contains(methods, socksMethodNoAuth) {
		client.Write([]byte{socksVersion, socksMethodNoAcceptable})
		return
	}

	// Reply: no auth
	if _, err := client.Write([]byte{socksVersion, socksMethodNoAuth}); err != nil {
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
	if req[1] != socksCmdConnect { // only CONNECT supported
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
	remote, viaUpstream, err := dial(upstream, target, dialTimeout)
	if err != nil {
		log.Printf("FAIL %s: %v", target.addr, err)
		var upstreamErr upstreamConnectError
		if errors.As(err, &upstreamErr) {
			sendReply(client, upstreamErr.rep)
			return
		}
		if errors.Is(err, errUpstreamProtocol) {
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

// readTarget parses the destination address from a SOCKS5 CONNECT request.
func readTarget(r io.Reader, atyp byte) (socks5Target, error) {
	var t socks5Target
	t.atyp = atyp

	switch atyp {
	case socksAtypIPv4: // IPv4
		buf := make([]byte, socksIPv4AddrLen+socksPortLen)
		if _, err := io.ReadFull(r, buf); err != nil {
			return t, err
		}
		t.ip = netip.AddrFrom4([socksIPv4AddrLen]byte(buf[:socksIPv4AddrLen]))
		t.port = binary.BigEndian.Uint16(buf[socksIPv4AddrLen : socksIPv4AddrLen+socksPortLen])

	case socksAtypDomain: // Domain
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

	case socksAtypIPv6: // IPv6
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

func replyCodeFromDialError(err error) byte {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return socksRepHostUnreachable
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return socksRepHostUnreachable
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNREFUSED:
			return socksRepConnectionRefused
		case syscall.ENETUNREACH:
			return socksRepNetworkUnreachable
		case syscall.EHOSTUNREACH, syscall.ETIMEDOUT:
			return socksRepHostUnreachable
		}
	}
	return socksRepGeneralFailure
}

// dial tries the upstream SOCKS5 proxy first; on failure, connects directly.
func dial(upstream string, target socks5Target, timeout time.Duration) (net.Conn, bool, error) {
	if upstreamBackoffCache.shouldSkip(upstream, time.Now()) {
		conn, err := net.DialTimeout("tcp", target.addr, directDialTimeout)
		if err != nil {
			return nil, false, err
		}
		return conn, false, nil
	}

	conn, err := dialUpstream(upstream, target, timeout)
	if err == nil {
		upstreamBackoffCache.clear(upstream)
		return conn, true, nil
	}
	var connectErr upstreamConnectError
	if errors.As(err, &connectErr) || errors.Is(err, errUpstreamProtocol) {
		return nil, false, err
	}
	if !errors.Is(err, errUpstreamUnavailable) {
		return nil, false, err
	}

	upstreamBackoffCache.markUnavailable(upstream, time.Now())
	log.Printf("upstream unavailable: %v; falling back to direct", err)
	conn, err = net.DialTimeout("tcp", target.addr, directDialTimeout)
	if err != nil {
		return nil, false, err
	}
	return conn, false, nil
}

// dialUpstream performs a full SOCKS5 handshake with the upstream proxy.
func dialUpstream(addr string, target socks5Target, timeout time.Duration) (net.Conn, error) {
	if timeout <= 0 {
		timeout = defaultUpstreamDialTimeout
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}
	ok := false
	defer func() {
		if !ok {
			conn.Close()
		}
	}()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}

	// Greeting
	if _, err := conn.Write([]byte{socksVersion, socksMethodSelectionCount, socksMethodNoAuth}); err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}
	resp := make([]byte, socksGreetingHeaderLen)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}
	if resp[0] != socksVersion || resp[1] != socksMethodNoAuth {
		return nil, fmt.Errorf("%w: auth response %x %x", errUpstreamProtocol, resp[0], resp[1])
	}

	// CONNECT request
	if _, err := conn.Write(buildConnectRequest(target)); err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
	}

	// Read reply header
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

	// Success. Zero value of time.Time means no deadline.
	conn.SetDeadline(time.Time{})
	ok = true
	return conn, nil
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

func relay(a, b net.Conn) {
	done := make(chan struct{})
	go func() {
		io.Copy(b, a)
		closeWrite(b)
		close(done)
	}()
	io.Copy(a, b)
	closeWrite(a)
	<-done
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}
