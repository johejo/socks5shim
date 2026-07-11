package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

const testIOTimeout = 2 * time.Second

func TestResolveVersion(t *testing.T) {
	origVersion := version
	t.Cleanup(func() {
		version = origVersion
	})

	version = "v9.9.9"
	if got := resolveVersion(); got != "v9.9.9" {
		t.Fatalf("resolveVersion() = %q, want %q", got, "v9.9.9")
	}
}

func TestHandleRejectsWhenNoNoAuthMethod(t *testing.T) {
	client, _ := startHandleSession(t, "127.0.0.1:9", 100*time.Millisecond, 100*time.Millisecond)
	writeGreeting(t, client, 0x02)

	resp := readN(t, client, 2)
	if !bytes.Equal(resp, []byte{socksVersion, socksMethodNoAcceptable}) {
		t.Fatalf("unexpected auth response: %x", resp)
	}
}

func TestHandleRejectsInvalidConnectHeader(t *testing.T) {
	client, _ := startHandleSession(t, "127.0.0.1:9", 100*time.Millisecond, 100*time.Millisecond)
	performClientNoAuthHandshake(t, client)

	// Bad VER in CONNECT header should be rejected before reading target bytes.
	if _, err := client.Write([]byte{0x04, socksCmdConnect, socksRSV, socksAtypIPv4}); err != nil {
		t.Fatalf("Write CONNECT header: %v", err)
	}
	reply := readN(t, client, 10)
	if reply[1] != socksRepGeneralFailure {
		t.Fatalf("unexpected rep code: 0x%02x", reply[1])
	}
}

func TestHandleRejectsUnsupportedAddressType(t *testing.T) {
	client, _ := startHandleSession(t, "127.0.0.1:9", 100*time.Millisecond, 100*time.Millisecond)
	performClientNoAuthHandshake(t, client)

	// Unknown ATYP must be mapped to REP=0x08.
	if _, err := client.Write([]byte{socksVersion, socksCmdConnect, socksRSV, 0x09}); err != nil {
		t.Fatalf("Write CONNECT header: %v", err)
	}
	reply := readN(t, client, 10)
	if reply[1] != socksRepAddressTypeNotSupp {
		t.Fatalf("unexpected rep code: 0x%02x", reply[1])
	}
}

func TestHandleTimesOutOnStalledClient(t *testing.T) {
	client, done := startHandleSession(t, "127.0.0.1:9", 100*time.Millisecond, 50*time.Millisecond)

	// Send only one byte of greeting then stall; handler should exit on deadline.
	if _, err := client.Write([]byte{socksVersion}); err != nil {
		t.Fatalf("Write partial greeting: %v", err)
	}
	waitDone(t, done)
}

func TestReadTargetDomainUsesJoinHostPort(t *testing.T) {
	// Domain may contain ':'; JoinHostPort must bracket it.
	domain := "2001:db8::1"
	payload := append([]byte{byte(len(domain))}, []byte(domain)...)
	payload = append(payload, 0x01, 0xbb) // 443

	tgt, err := readTarget(bytes.NewReader(payload), socksAtypDomain)
	if err != nil {
		t.Fatalf("readTarget: %v", err)
	}
	if tgt.addr != "[2001:db8::1]:443" {
		t.Fatalf("unexpected addr: %q", tgt.addr)
	}
}

func TestReadTargetRejectsEmptyDomain(t *testing.T) {
	_, err := readTarget(bytes.NewReader([]byte{0x00}), socksAtypDomain)
	if err == nil || !strings.Contains(err.Error(), "empty domain") {
		t.Fatalf("expected empty domain error, got: %v", err)
	}
}

func TestDialUpstreamRejectsInvalidReplyHeader(t *testing.T) {
	skipIfShortNetwork(t)

	ln := mustListenLoopback(t, "upstream")

	target := socks5Target{
		atyp: socksAtypIPv4,
		ip:   netip.MustParseAddr("1.2.3.4"),
		port: 443,
		addr: "1.2.3.4:443",
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		if err := performUpstreamNoAuthHandshake(conn, target); err != nil {
			serverErr <- err
			return
		}

		// Invalid VER in upstream CONNECT reply header.
		if _, err := conn.Write([]byte{0x04, socksRepSucceeded, socksRSV, socksAtypIPv4}); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	_, err := dialUpstream(ln.Addr().String(), target, 2*time.Second, 2*time.Second)
	if err == nil || !errors.Is(err, errUpstreamProtocol) || !strings.Contains(err.Error(), "reply header") {
		t.Fatalf("expected upstream reply header error, got: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

func TestDialDoesNotFallbackOnUpstreamConnectFailure(t *testing.T) {
	skipIfShortNetwork(t)

	upstreamLn := mustListenLoopback(t, "upstream")

	targetLn := mustListenLoopback(t, "target")

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err == nil {
			conn.Close()
			accepted <- struct{}{}
		}
	}()

	target := targetFromListener(t, targetLn)

	serverErr := make(chan error, 1)
	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		if err := performUpstreamNoAuthHandshake(conn, target); err != nil {
			serverErr <- err
			return
		}

		// Upstream policy denial. dial() must not bypass via direct fallback.
		if _, err := conn.Write([]byte{socksVersion, 0x02, socksRSV, socksAtypIPv4}); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	conn, viaUpstream, err := dial(upstreamLn.Addr().String(), target, 200*time.Millisecond, 200*time.Millisecond)
	if conn != nil {
		conn.Close()
		t.Fatalf("expected nil conn on upstream policy failure")
	}
	if viaUpstream {
		t.Fatalf("unexpected viaUpstream=true")
	}
	var connectErr upstreamConnectError
	if !errors.As(err, &connectErr) || connectErr.rep != 0x02 {
		t.Fatalf("expected upstreamConnectError rep=0x02, got: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}

	select {
	case <-accepted:
		t.Fatal("direct fallback occurred unexpectedly")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestDialFallsBackOnUpstreamDialFailure(t *testing.T) {
	skipIfShortNetwork(t)

	tests := []struct {
		name string
		rep  byte
	}{
		{name: "general failure", rep: socksRepGeneralFailure},
		{name: "network unreachable", rep: socksRepNetworkUnreachable},
		{name: "host unreachable", rep: socksRepHostUnreachable},
		{name: "connection refused", rep: socksRepConnectionRefused},
		{name: "ttl expired", rep: socksRepTTLExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Upstream-side dial failure.
			fx := startDialFallbackFixture(t, []byte{socksVersion, tt.rep, socksRSV, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
			fx.assertDirectFallback(t, 200*time.Millisecond, 200*time.Millisecond)
			if upstreamBackoffCache.shouldSkip(fx.upstreamAddr, time.Now()) {
				t.Fatal("backoff cache must not be marked on CONNECT rep failure")
			}
		})
	}
}

func TestDialFallsBackOnConnectReplyTimeout(t *testing.T) {
	skipIfShortNetwork(t)

	// Upstream completes the greeting, then never answers the CONNECT request.
	fx := startDialFallbackFixture(t, nil)
	fx.assertDirectFallback(t, time.Second, 200*time.Millisecond)
	if !upstreamBackoffCache.shouldSkip(fx.upstreamAddr, time.Now()) {
		t.Fatal("backoff cache must be marked on CONNECT reply timeout")
	}
}

type dialFallbackFixture struct {
	upstreamAddr string
	target       socks5Target
	accepted     chan struct{}
	serverErr    chan error
}

// startDialFallbackFixture starts a target listener that signals when it is
// dialed and a mock upstream that completes the greeting, then writes
// connectReply. An empty connectReply makes the upstream stall until cleanup.
func startDialFallbackFixture(t *testing.T, connectReply []byte) dialFallbackFixture {
	t.Helper()

	upstreamLn := mustListenLoopback(t, "upstream")
	targetLn := mustListenLoopback(t, "target")
	target := targetFromListener(t, targetLn)

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := targetLn.Accept()
		if err == nil {
			conn.Close()
			accepted <- struct{}{}
		}
	}()

	upstreamAddr := upstreamLn.Addr().String()
	upstreamBackoffCache.clear(upstreamAddr)
	t.Cleanup(func() { upstreamBackoffCache.clear(upstreamAddr) })

	var stall chan struct{}
	if len(connectReply) == 0 {
		stall = make(chan struct{})
		t.Cleanup(func() { close(stall) })
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		if err := performUpstreamNoAuthHandshake(conn, target); err != nil {
			serverErr <- err
			return
		}
		if len(connectReply) == 0 {
			serverErr <- nil
			<-stall
			return
		}
		_, err = conn.Write(connectReply)
		serverErr <- err
	}()

	return dialFallbackFixture{
		upstreamAddr: upstreamAddr,
		target:       target,
		accepted:     accepted,
		serverErr:    serverErr,
	}
}

// assertDirectFallback runs dial and checks it fell back to a direct
// connection to the target.
func (fx dialFallbackFixture) assertDirectFallback(t *testing.T, helloTimeout, connectTimeout time.Duration) {
	t.Helper()

	conn, viaUpstream, err := dial(fx.upstreamAddr, fx.target, helloTimeout, connectTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if viaUpstream {
		t.Fatal("expected direct fallback, got viaUpstream=true")
	}
	if err := <-fx.serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}

	select {
	case <-fx.accepted:
	case <-time.After(time.Second):
		t.Fatal("target was not dialed directly")
	}
}

func TestDialUpstreamAllowsConnectReplySlowerThanHelloTimeout(t *testing.T) {
	skipIfShortNetwork(t)

	upstreamLn := mustListenLoopback(t, "upstream")

	target := socks5Target{
		atyp: socksAtypIPv4,
		ip:   netip.MustParseAddr("1.2.3.4"),
		port: 443,
		addr: "1.2.3.4:443",
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		if err := performUpstreamNoAuthHandshake(conn, target); err != nil {
			serverErr <- err
			return
		}

		// Reply well after helloTimeout but within connectTimeout.
		time.Sleep(600 * time.Millisecond)
		reply := []byte{socksVersion, socksRepSucceeded, socksRSV, socksAtypIPv4, 127, 0, 0, 1, 0x12, 0x34}
		if _, err := conn.Write(reply); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	conn, err := dialUpstream(upstreamLn.Addr().String(), target, 200*time.Millisecond, 5*time.Second)
	if err != nil {
		t.Fatalf("dialUpstream: %v", err)
	}
	conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

func TestHandleSuccessfulConnectAndRelayViaUpstream(t *testing.T) {
	skipIfShortNetwork(t)

	upstreamLn := mustListenLoopback(t, "upstream")

	target := socks5Target{
		atyp: socksAtypIPv4,
		ip:   netip.MustParseAddr("1.2.3.4"),
		port: 443,
		addr: "1.2.3.4:443",
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, err := upstreamLn.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		setDeadline(t, conn, testIOTimeout)
		if err := performUpstreamNoAuthHandshake(conn, target); err != nil {
			serverErr <- err
			return
		}

		reply := []byte{socksVersion, socksRepSucceeded, socksRSV, socksAtypIPv4, 127, 0, 0, 1, 0x12, 0x34}
		if _, err := conn.Write(reply); err != nil {
			serverErr <- err
			return
		}

		payload := make([]byte, 4)
		if _, err := io.ReadFull(conn, payload); err != nil {
			serverErr <- err
			return
		}
		if string(payload) != "ping" {
			serverErr <- fmt.Errorf("unexpected relay payload: %q", payload)
			return
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	client, _ := startHandleSession(t, upstreamLn.Addr().String(), 200*time.Millisecond, 200*time.Millisecond)
	performClientNoAuthHandshake(t, client)

	if _, err := client.Write(buildConnectRequest(target)); err != nil {
		t.Fatalf("Write CONNECT request: %v", err)
	}
	reply := readN(t, client, 10)
	if reply[0] != socksVersion || reply[1] != socksRepSucceeded || reply[3] != socksAtypIPv4 {
		t.Fatalf("unexpected CONNECT reply: %x", reply)
	}

	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("Write relay payload: %v", err)
	}
	if got := string(readN(t, client, 4)); got != "pong" {
		t.Fatalf("unexpected relay response: %q", got)
	}

	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

func TestDialMarksUnavailableBackoff(t *testing.T) {
	upstreamAddr := "127.0.0.1:1"
	upstreamBackoffCache.clear(upstreamAddr)
	t.Cleanup(func() { upstreamBackoffCache.clear(upstreamAddr) })

	target := socks5Target{
		atyp: socksAtypIPv4,
		ip:   netip.MustParseAddr("127.0.0.1"),
		port: 1,
		addr: "127.0.0.1:1",
	}

	_, _, _ = dial(upstreamAddr, target, 100*time.Millisecond, 100*time.Millisecond)
	if !upstreamBackoffCache.shouldSkip(upstreamAddr, time.Now()) {
		t.Fatal("expected upstream backoff cache to be marked unavailable")
	}
}

func TestReplyCodeFromDialError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want byte
	}{
		{name: "refused", err: syscall.ECONNREFUSED, want: socksRepConnectionRefused},
		{name: "network unreachable", err: syscall.ENETUNREACH, want: socksRepNetworkUnreachable},
		{name: "host unreachable", err: syscall.EHOSTUNREACH, want: socksRepHostUnreachable},
		{name: "timeout errno", err: syscall.ETIMEDOUT, want: socksRepHostUnreachable},
		{name: "dns error", err: &net.DNSError{Err: "no such host", Name: "x.invalid"}, want: socksRepHostUnreachable},
		{name: "fallback", err: errors.New("other"), want: socksRepGeneralFailure},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := replyCodeFromDialError(tt.err); got != tt.want {
				t.Fatalf("replyCodeFromDialError(%v) = 0x%02x, want 0x%02x", tt.err, got, tt.want)
			}
		})
	}
}

func TestSendReplyWithBindUsesActualIPv4Bind(t *testing.T) {
	var buf bytes.Buffer
	sendReplyWithBind(&buf, socksRepSucceeded, &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 1080,
	})

	want := []byte{socksVersion, socksRepSucceeded, socksRSV, socksAtypIPv4, 127, 0, 0, 1, 0x04, 0x38}
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("unexpected reply bytes: %x", buf.Bytes())
	}
}

func TestSendReplyWithBindUsesActualIPv6Bind(t *testing.T) {
	var buf bytes.Buffer
	sendReplyWithBind(&buf, socksRepSucceeded, &net.TCPAddr{
		IP:   netip.MustParseAddr("2001:db8::1").AsSlice(),
		Port: 8080,
	})

	want := []byte{socksVersion, socksRepSucceeded, socksRSV, socksAtypIPv6}
	want = append(want, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	want = append(want, 0x1f, 0x90) // 8080
	if !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("unexpected reply bytes: %x", buf.Bytes())
	}
}

func startHandleSession(t *testing.T, upstream string, dialTimeout, clientReadTimeout time.Duration) (net.Conn, chan struct{}) {
	t.Helper()
	client, server := testClientServer(t)
	done := make(chan struct{})
	go func() {
		handle(server, upstream, dialTimeout, dialTimeout, clientReadTimeout)
		close(done)
	}()
	setDeadline(t, client, testIOTimeout)
	t.Cleanup(func() {
		client.Close()
		waitDone(t, done)
	})
	return client, done
}

func writeGreeting(t *testing.T, client net.Conn, methods ...byte) {
	t.Helper()
	greeting := append([]byte{socksVersion, byte(len(methods))}, methods...)
	if _, err := client.Write(greeting); err != nil {
		t.Fatalf("Write greeting: %v", err)
	}
}

func performClientNoAuthHandshake(t *testing.T, client net.Conn) {
	t.Helper()
	writeGreeting(t, client, socksMethodNoAuth)
	authResp := readN(t, client, 2)
	if !bytes.Equal(authResp, []byte{socksVersion, socksMethodNoAuth}) {
		t.Fatalf("unexpected auth response: %x", authResp)
	}
}

func performUpstreamNoAuthHandshake(conn net.Conn, target socks5Target) error {
	greeting := make([]byte, socksGreetingHeaderLen+1)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return err
	}
	if !bytes.Equal(greeting, []byte{socksVersion, socksMethodSelectionCount, socksMethodNoAuth}) {
		return fmt.Errorf("unexpected upstream greeting: %x", greeting)
	}
	if _, err := conn.Write([]byte{socksVersion, socksMethodNoAuth}); err != nil {
		return err
	}

	expectedReq := buildConnectRequest(target)
	req := make([]byte, len(expectedReq))
	if _, err := io.ReadFull(conn, req); err != nil {
		return err
	}
	if !bytes.Equal(req, expectedReq) {
		return fmt.Errorf("unexpected CONNECT request: %x", req)
	}
	return nil
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("ReadFull(%d): %v", n, err)
	}
	return buf
}

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting handler to exit")
	}
}

func skipIfShortNetwork(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping network access test in -short mode")
	}
}

func testClientServer(t *testing.T) (client net.Conn, server net.Conn) {
	t.Helper()
	client, server = net.Pipe()
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

func mustListenLoopback(t *testing.T, name string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if isPermissionDenied(err) {
			t.Skipf("skipping %s bind test in restricted environment: %v", name, err)
		}
		t.Fatalf("Listen %s: %v", name, err)
	}
	t.Cleanup(func() {
		ln.Close()
	})
	return ln
}

func targetFromListener(t *testing.T, ln net.Listener) socks5Target {
	t.Helper()
	tcpAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", ln.Addr())
	}
	addrPort := tcpAddr.AddrPort()
	return socks5Target{
		atyp: socksAtypIPv4,
		ip:   addrPort.Addr().Unmap(),
		port: addrPort.Port(),
		addr: addrPort.String(),
	}
}

func setDeadline(t *testing.T, conn net.Conn, timeout time.Duration) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
}

func TestHandleHTTPConnect(t *testing.T) {
	skipIfShortNetwork(t)

	// Start a target TCP server that echoes data.
	targetLn := mustListenLoopback(t, "target")
	go func() {
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()

	// Connect to the HTTP proxy and send a CONNECT request.
	proxyAddr := startHTTPProxyStack(t, targetLn.Addr().String())
	conn := dialHTTPProxy(t, proxyAddr)

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetLn.Addr().String(), targetLn.Addr().String())

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	// Tunnel is established; send data through.
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	echoed := readN(t, br, 5)
	if string(echoed) != "hello" {
		t.Fatalf("unexpected echo: %q", echoed)
	}
}

func TestHandleHTTPPlainGET(t *testing.T) {
	skipIfShortNetwork(t)

	// Start a target HTTP server.
	targetLn := mustListenLoopback(t, "target")
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				if req.URL.Path != "/test" {
					fmt.Fprintf(c, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
					return
				}
				body := "OK"
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
			}(conn)
		}
	}()

	// Send a plain HTTP GET through the proxy.
	proxyAddr := startHTTPProxyStack(t, "")
	conn := dialHTTPProxy(t, proxyAddr)

	targetAddr := targetLn.Addr().String()
	fmt.Fprintf(conn, "GET http://%s/test HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetAddr, targetAddr)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "OK" {
		t.Fatalf("unexpected body: %q", body)
	}
}

func TestHandleHTTPPlainStripsProxyHeaders(t *testing.T) {
	skipIfShortNetwork(t)

	// Target server that echoes back received headers.
	targetLn := mustListenLoopback(t, "target")
	go func() {
		for {
			conn, err := targetLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				// Report whether proxy headers were forwarded.
				hasProxyConn := req.Header.Get("Proxy-Connection")
				hasProxyAuth := req.Header.Get("Proxy-Authorization")
				body := fmt.Sprintf("proxy-connection=%q proxy-authorization=%q", hasProxyConn, hasProxyAuth)
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(conn)
		}
	}()

	proxyAddr := startHTTPProxyStack(t, "")
	conn := dialHTTPProxy(t, proxyAddr)

	targetAddr := targetLn.Addr().String()
	fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nConnection: close\r\n\r\n", targetAddr, targetAddr)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)
	if !strings.Contains(bodyStr, `proxy-connection=""`) {
		t.Fatalf("Proxy-Connection was not stripped: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, `proxy-authorization=""`) {
		t.Fatalf("Proxy-Authorization was not stripped: %s", bodyStr)
	}
}

func TestHandleHTTPRejectsInvalidProto(t *testing.T) {
	client, server := testClientServer(t)
	done := make(chan struct{})
	go func() {
		handleHTTP(server, "127.0.0.1:9", 100*time.Millisecond, 100*time.Millisecond, 100*time.Millisecond)
		close(done)
	}()
	setDeadline(t, client, testIOTimeout)

	// Send a request with a bogus protocol version.
	fmt.Fprintf(client, "GET / HTTP/2.0\r\nHost: example.com\r\n\r\n")

	// The handler should close the connection because proto is not HTTP/1.0 or HTTP/1.1.
	waitDone(t, done)
}

// startHTTPProxyStack starts a mock upstream SOCKS5 proxy and an HTTP proxy
// listener in front of it, returning the HTTP proxy address. fixedTarget is
// passed through to serveMockUpstream.
func startHTTPProxyStack(t *testing.T, fixedTarget string) string {
	t.Helper()

	upstreamLn := mustListenLoopback(t, "upstream")
	go func() {
		for {
			conn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go serveMockUpstream(conn, fixedTarget)
		}
	}()

	httpLn := mustListenLoopback(t, "http-proxy")
	go func() {
		for {
			conn, err := httpLn.Accept()
			if err != nil {
				return
			}
			go handleHTTP(conn, upstreamLn.Addr().String(), testIOTimeout, testIOTimeout, testIOTimeout)
		}
	}()
	return httpLn.Addr().String()
}

func dialHTTPProxy(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, testIOTimeout)
	if err != nil {
		t.Fatalf("dial HTTP proxy: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	setDeadline(t, conn, testIOTimeout)
	return conn
}

// serveMockUpstream is a minimal SOCKS5 server that connects to real targets.
// If fixedTarget is non-empty, it dials that address regardless of what the
// client requests (useful for redirecting to a test server).
func serveMockUpstream(conn net.Conn, fixedTarget string) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting.
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	conn.Write([]byte{socksVersion, socksMethodNoAuth})

	// CONNECT request.
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHdr); err != nil {
		return
	}
	target, err := readTarget(conn, reqHdr[3])
	if err != nil {
		return
	}

	dialAddr := target.addr
	if fixedTarget != "" {
		dialAddr = fixedTarget
	}

	remote, err := net.DialTimeout("tcp", dialAddr, 2*time.Second)
	if err != nil {
		conn.Write([]byte{socksVersion, socksRepHostUnreachable, socksRSV, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	defer remote.Close()

	conn.Write([]byte{socksVersion, socksRepSucceeded, socksRSV, socksAtypIPv4, 127, 0, 0, 1, 0, 0})
	conn.SetDeadline(time.Time{})

	done := make(chan struct{})
	go func() {
		io.Copy(remote, conn)
		close(done)
	}()
	io.Copy(conn, remote)
	<-done
}

func isPermissionDenied(err error) bool {
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno == syscall.EPERM || errno == syscall.EACCES
	}
	return false
}
