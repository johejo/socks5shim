package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"net/url"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
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
	socksRepTTLExpired          = 0x06
	socksRepCommandNotSupported = 0x07
	socksRepAddressTypeNotSupp  = 0x08

	socksGreetingHeaderLen = 2
	socksConnectHeaderLen  = 4
	socksIPv4AddrLen       = 4
	socksIPv6AddrLen       = 16
	socksPortLen           = 2

	defaultUpstreamDialTimeout    = 2 * time.Second
	defaultUpstreamConnectTimeout = 7 * time.Second
	defaultClientReadTimeout      = 5 * time.Second
	directDialTimeout             = 10 * time.Second
	upstreamUnavailableBackoff    = 3 * time.Second

	maxHTTPLineLength = 8 << 10
)

var errAddressTypeNotSupported = errors.New("address type not supported")
var errHTTPLineTooLong = errors.New("http line too long")
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

// fallbackEligible reports whether the reply code is a connection failure
// that may not recur on a direct path, safe to retry. Deliberate rejections
// (0x02) and capability mismatches (0x07/0x08) are not.
func (e upstreamConnectError) fallbackEligible() bool {
	switch e.rep {
	case socksRepGeneralFailure, socksRepNetworkUnreachable, socksRepHostUnreachable,
		socksRepConnectionRefused, socksRepTTLExpired:
		return true
	}
	return false
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
	httpListen := flag.String("http-listen", "", "HTTP proxy listen address (empty to disable)")
	upstream := flag.String("upstream", "127.0.0.1:1080", "upstream SOCKS5 proxy address")
	dialTimeout := flag.Duration("dial-timeout", defaultUpstreamDialTimeout, "timeout for TCP connect and SOCKS5 greeting to upstream")
	connectTimeout := flag.Duration("connect-timeout", defaultUpstreamConnectTimeout, "timeout for SOCKS5 CONNECT reply from upstream")
	clientReadTimeout := flag.Duration("client-handshake-timeout", defaultClientReadTimeout, "timeout for reading SOCKS5 greeting/request from client")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(resolveVersion())
		return
	}

	if *httpListen != "" {
		httpLn, err := net.Listen("tcp", *httpListen)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("HTTP proxy listening on %s, upstream %s (dial-timeout %s, connect-timeout %s)", *httpListen, *upstream, *dialTimeout, *connectTimeout)
		go acceptLoop(httpLn, "http", func(conn net.Conn) {
			handleHTTP(conn, *upstream, *dialTimeout, *connectTimeout, *clientReadTimeout)
		})
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SOCKS5 listening on %s, upstream %s (dial-timeout %s, connect-timeout %s)", *listen, *upstream, *dialTimeout, *connectTimeout)

	acceptLoop(ln, "socks5", func(conn net.Conn) {
		handle(conn, *upstream, *dialTimeout, *connectTimeout, *clientReadTimeout)
	})
}

// acceptLoop retries Accept errors with backoff so a persistent failure such
// as EMFILE does not busy-spin.
func acceptLoop(ln net.Listener, name string, handler func(net.Conn)) {
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else {
				delay *= 2
			}
			if maxDelay := 1 * time.Second; delay > maxDelay {
				delay = maxDelay
			}
			log.Printf("%s accept: %v; retrying in %s", name, err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		go handler(conn)
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

func handle(client net.Conn, upstream string, dialTimeout, connectTimeout, clientReadTimeout time.Duration) {
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
	remote, viaUpstream, err := dial(upstream, target, dialTimeout, connectTimeout)
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
func dial(upstream string, target socks5Target, helloTimeout, connectTimeout time.Duration) (net.Conn, bool, error) {
	if upstreamBackoffCache.shouldSkip(upstream, time.Now()) {
		return dialDirect(target)
	}

	conn, err := dialUpstream(upstream, target, helloTimeout, connectTimeout)
	if err == nil {
		upstreamBackoffCache.clear(upstream)
		return conn, true, nil
	}
	var connectErr upstreamConnectError
	if errors.As(err, &connectErr) {
		if !connectErr.fallbackEligible() {
			return nil, false, err
		}
		// The greeting succeeded, so the upstream is alive: fall back
		// without poisoning the backoff cache.
		upstreamBackoffCache.clear(upstream)
		log.Printf("upstream CONNECT failed (rep=0x%02x) for %s; falling back to direct", connectErr.rep, target.addr)
		return dialDirect(target)
	}
	if !errors.Is(err, errUpstreamUnavailable) {
		return nil, false, err
	}

	// Covers CONNECT reply timeouts too: back off so a wedged upstream
	// doesn't stall every connection for connectTimeout.
	upstreamBackoffCache.markUnavailable(upstream, time.Now())
	log.Printf("upstream unavailable: %v; falling back to direct", err)
	return dialDirect(target)
}

func dialDirect(target socks5Target) (net.Conn, bool, error) {
	conn, err := net.DialTimeout("tcp", target.addr, directDialTimeout)
	if err != nil {
		return nil, false, err
	}
	return conn, false, nil
}

// dialUpstream performs a full SOCKS5 handshake with the upstream proxy.
// helloTimeout covers TCP connect + greeting; connectTimeout covers the
// CONNECT request/reply (includes the upstream-side dial to the target).
func dialUpstream(addr string, target socks5Target, helloTimeout, connectTimeout time.Duration) (net.Conn, error) {
	if helloTimeout <= 0 {
		helloTimeout = defaultUpstreamDialTimeout
	}
	if connectTimeout <= 0 {
		connectTimeout = defaultUpstreamConnectTimeout
	}
	conn, err := net.DialTimeout("tcp", addr, helloTimeout)
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

	// The CONNECT reply waits on the upstream-side dial, so it gets its own deadline.
	if err := conn.SetDeadline(time.Now().Add(connectTimeout)); err != nil {
		return nil, fmt.Errorf("%w: %v", errUpstreamUnavailable, err)
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

func handleHTTP(client net.Conn, upstream string, dialTimeout, connectTimeout, clientReadTimeout time.Duration) {
	defer client.Close()
	if clientReadTimeout <= 0 {
		clientReadTimeout = defaultClientReadTimeout
	}
	if err := client.SetReadDeadline(time.Now().Add(clientReadTimeout)); err != nil {
		return
	}

	br := bufio.NewReaderSize(client, maxHTTPLineLength)
	requestLine, err := readHTTPLine(br)
	if err != nil {
		respondLineTooLong(client, "HTTP/1.1", err)
		return
	}
	requestLine = strings.TrimRight(requestLine, "\r\n")

	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) != 3 {
		return
	}
	method, uri, proto := parts[0], parts[1], parts[2]

	// Validate protocol version to prevent header injection.
	if proto != "HTTP/1.0" && proto != "HTTP/1.1" {
		return
	}

	if strings.ToUpper(method) == "CONNECT" {
		handleHTTPConnect(client, br, uri, proto, upstream, dialTimeout, connectTimeout)
	} else {
		handleHTTPPlain(client, br, method, uri, proto, upstream, dialTimeout, connectTimeout)
	}
}

// readHTTPLine reads one line, failing instead of buffering unboundedly
// when no newline arrives within the reader's buffer size.
func readHTTPLine(br *bufio.Reader) (string, error) {
	line, err := br.ReadSlice('\n')
	if err == bufio.ErrBufferFull {
		return "", errHTTPLineTooLong
	}
	if err != nil {
		return "", err
	}
	return string(line), nil
}

// respondLineTooLong writes a best-effort 431 if err is errHTTPLineTooLong.
func respondLineTooLong(client net.Conn, proto string, err error) {
	if errors.Is(err, errHTTPLineTooLong) {
		client.Write([]byte(proto + " 431 Request Header Fields Too Large\r\n\r\n"))
	}
}

func handleHTTPConnect(client net.Conn, br *bufio.Reader, uri, proto, upstream string, dialTimeout, connectTimeout time.Duration) {
	// Read and discard headers until empty line.
	for {
		line, err := readHTTPLine(br)
		if err != nil {
			respondLineTooLong(client, proto, err)
			return
		}
		if strings.TrimRight(line, "\r\n") == "" {
			break
		}
	}

	host, port, err := parseHostPort(uri, "443")
	if err != nil {
		client.Write([]byte(proto + " 400 Bad Request\r\n\r\n"))
		return
	}

	target := buildHTTPTarget(host, port)
	remote, viaUpstream, err := dial(upstream, target, dialTimeout, connectTimeout)
	if err != nil {
		log.Printf("HTTP CONNECT FAIL %s: %v", target.addr, err)
		client.Write([]byte(proto + " 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	if viaUpstream {
		log.Printf("HTTP CONNECT PROXY %s", target.addr)
	} else {
		log.Printf("HTTP CONNECT DIRECT %s -> %s", target.addr, remote.RemoteAddr())
	}

	if err := client.SetReadDeadline(time.Time{}); err != nil {
		return
	}
	client.Write([]byte(proto + " 200 Connection established\r\n\r\n"))

	// Flush any data already buffered by bufio.Reader before relaying.
	if n := br.Buffered(); n > 0 {
		buffered, _ := br.Peek(n)
		if _, err := remote.Write(buffered); err != nil {
			return
		}
		br.Discard(n)
	}

	relay(client, remote)
}

func handleHTTPPlain(client net.Conn, br *bufio.Reader, method, uri, proto, upstream string, dialTimeout, connectTimeout time.Duration) {
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		client.Write([]byte(proto + " 400 Bad Request\r\n\r\n"))
		return
	}

	host, port, err := parseHostPort(u.Host, "80")
	if err != nil {
		client.Write([]byte(proto + " 400 Bad Request\r\n\r\n"))
		return
	}

	target := buildHTTPTarget(host, port)
	remote, viaUpstream, err := dial(upstream, target, dialTimeout, connectTimeout)
	if err != nil {
		log.Printf("HTTP PLAIN FAIL %s: %v", target.addr, err)
		client.Write([]byte(proto + " 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	if viaUpstream {
		log.Printf("HTTP PLAIN PROXY %s", target.addr)
	} else {
		log.Printf("HTTP PLAIN DIRECT %s -> %s", target.addr, remote.RemoteAddr())
	}

	// Rewrite request line to relative path.
	path := u.RequestURI()
	if _, err := fmt.Fprintf(remote, "%s %s %s\r\n", method, path, proto); err != nil {
		return
	}

	// Forward headers, removing hop-by-hop Proxy-* headers.
	// Force Connection: close so neither side reuses the connection;
	// relay() forwards raw bytes and cannot route a second request.
	for {
		line, err := readHTTPLine(br)
		if err != nil {
			respondLineTooLong(client, proto, err)
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			remote.Write([]byte("Connection: close\r\n\r\n"))
			break
		}
		lower := strings.ToLower(trimmed)
		if strings.HasPrefix(lower, "proxy-connection:") || strings.HasPrefix(lower, "proxy-authorization:") || strings.HasPrefix(lower, "connection:") || strings.HasPrefix(lower, "keep-alive:") {
			continue
		}
		remote.Write([]byte(line))
	}

	if err := client.SetReadDeadline(time.Time{}); err != nil {
		return
	}

	// Flush any data already buffered by bufio.Reader before relaying.
	if n := br.Buffered(); n > 0 {
		buffered, _ := br.Peek(n)
		if _, err := remote.Write(buffered); err != nil {
			return
		}
		br.Discard(n)
	}

	relay(client, remote)
}

func parseHostPort(hostport, defaultPort string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		// No port specified; treat whole string as host.
		host = hostport
		portStr = defaultPort
	}
	// buildConnectRequest encodes the domain length as a single byte;
	// byte(len) silently truncates mod 256, so reject oversized hosts here.
	if host == "" || len(host) > 255 {
		return "", 0, fmt.Errorf("invalid host length: %d", len(host))
	}
	p, err := strconv.Atoi(portStr)
	if err != nil || p <= 0 || p > 65535 {
		return "", 0, fmt.Errorf("invalid port: %s", portStr)
	}
	return host, uint16(p), nil
}

func buildHTTPTarget(host string, port uint16) socks5Target {
	t := socks5Target{port: port}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			t.atyp = socksAtypIPv4
		} else {
			t.atyp = socksAtypIPv6
		}
		t.ip = ip
		t.addr = netip.AddrPortFrom(ip, port).String()
	} else {
		t.atyp = socksAtypDomain
		t.domain = host
		t.addr = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}
	return t
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
