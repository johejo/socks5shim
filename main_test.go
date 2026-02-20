package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
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

	_, err := dialUpstream(ln.Addr().String(), target, 2*time.Second)
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

	targetTCPAddr, ok := targetLn.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("expected *net.TCPAddr, got %T", targetLn.Addr())
	}
	targetAddrPort := targetTCPAddr.AddrPort()
	target := socks5Target{
		atyp: socksAtypIPv4,
		ip:   targetAddrPort.Addr().Unmap(),
		port: targetAddrPort.Port(),
		addr: targetAddrPort.String(),
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

		// Upstream policy denial. dial() must not bypass via direct fallback.
		if _, err := conn.Write([]byte{socksVersion, 0x02, socksRSV, socksAtypIPv4}); err != nil {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	conn, viaUpstream, err := dial(upstreamLn.Addr().String(), target, 200*time.Millisecond)
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

	_, _, _ = dial(upstreamAddr, target, 100*time.Millisecond)
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
		handle(server, upstream, dialTimeout, clientReadTimeout)
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

func setDeadline(t *testing.T, conn net.Conn, timeout time.Duration) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
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
