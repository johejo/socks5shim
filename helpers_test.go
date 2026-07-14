package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

const testIOTimeout = 2 * time.Second

// newTestProxy returns a proxy with a fresh backoff cache and generous
// timeouts; tests exercising timeout expiry override individual fields.
func newTestProxy(upstream string) *proxy {
	return &proxy{
		upstream:          upstream,
		dialTimeout:       testIOTimeout,
		connectTimeout:    testIOTimeout,
		clientReadTimeout: testIOTimeout,
		backoff:           newUpstreamBackoffState(upstreamUnavailableBackoff),
	}
}

func performUpstreamNoAuthHandshake(conn net.Conn, target socks5Target) error {
	greeting := make([]byte, socksGreetingHeaderLen+1)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return err
	}
	if !bytes.Equal(greeting, []byte{socksVersion, 0x01, socksMethodNoAuth}) {
		return fmt.Errorf("unexpected upstream greeting: %x", greeting)
	}
	if _, err := conn.Write([]byte{socksVersion, socksMethodNoAuth}); err != nil {
		return err
	}
	return expectConnectRequest(conn, target)
}

// performUpstreamUserPassHandshake returns a handshake that selects the
// username/password method, verifies the RFC 1929 subnegotiation carries
// wantUser/wantPass, and accepts it.
func performUpstreamUserPassHandshake(wantUser, wantPass string) func(net.Conn, socks5Target) error {
	return func(conn net.Conn, target socks5Target) error {
		if err := expectGreetingWithUserPass(conn); err != nil {
			return err
		}
		if _, err := conn.Write([]byte{socksVersion, socksMethodUserPass}); err != nil {
			return err
		}

		creds, err := readUserPassAuth(conn)
		if err != nil {
			return err
		}
		if creds.username != wantUser || creds.password != wantPass {
			return fmt.Errorf("unexpected credentials: %q/%q", creds.username, creds.password)
		}
		if _, err := conn.Write([]byte{socksUserPassVersion, socksUserPassSuccess}); err != nil {
			return err
		}
		return expectConnectRequest(conn, target)
	}
}

// expectGreetingWithUserPass reads a 4-byte upstream greeting and checks it
// offers exactly no-auth plus username/password.
func expectGreetingWithUserPass(conn net.Conn) error {
	greeting := make([]byte, socksGreetingHeaderLen+2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return err
	}
	if !bytes.Equal(greeting, []byte{socksVersion, 0x02, socksMethodNoAuth, socksMethodUserPass}) {
		return fmt.Errorf("unexpected upstream greeting: %x", greeting)
	}
	return nil
}

// userPassHandshakeReplying returns an upstream handshake that selects the
// username/password method, reads the RFC 1929 subnegotiation, and answers
// it with reply (a reply that just returns closes the connection).
func userPassHandshakeReplying(reply func(net.Conn) error) func(net.Conn, socks5Target) error {
	return func(conn net.Conn, _ socks5Target) error {
		if err := expectGreetingWithUserPass(conn); err != nil {
			return err
		}
		if _, err := conn.Write([]byte{socksVersion, socksMethodUserPass}); err != nil {
			return err
		}
		if _, err := readUserPassAuth(conn); err != nil {
			return err
		}
		return reply(conn)
	}
}

// rejectUserPassAuth answers an RFC 1929 subnegotiation with a non-zero
// STATUS byte.
func rejectUserPassAuth(conn net.Conn) error {
	_, err := conn.Write([]byte{socksUserPassVersion, 0x01})
	return err
}

func expectConnectRequest(conn net.Conn, target socks5Target) error {
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

// startScriptedUpstream starts a mock SOCKS5 upstream that accepts one
// connection, verifies the greeting and CONNECT request for target, then
// runs script on the connection. The returned channel receives the script's
// result (or the earlier accept/handshake error).
func startScriptedUpstream(t *testing.T, target socks5Target, script func(net.Conn) error) (addr string, serverErr chan error) {
	t.Helper()
	return startScriptedUpstreamHandshake(t, target, performUpstreamNoAuthHandshake, script)
}

// startScriptedUpstreamHandshake is startScriptedUpstream with a custom
// greeting/auth handshake (e.g. performUpstreamUserPassHandshake).
func startScriptedUpstreamHandshake(t *testing.T, target socks5Target, handshake func(net.Conn, socks5Target) error, script func(net.Conn) error) (addr string, serverErr chan error) {
	t.Helper()
	ln := mustListenLoopback(t, "upstream")
	serverErr = make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))

		if err := handshake(conn, target); err != nil {
			serverErr <- err
			return
		}
		serverErr <- script(conn)
	}()
	return ln.Addr().String(), serverErr
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

// startWatchedTarget starts a reachable target listener that signals on the
// returned channel when it is dialed, so tests can assert whether a direct
// connection to the target happened.
func startWatchedTarget(t *testing.T) (socks5Target, chan struct{}) {
	t.Helper()
	ln := mustListenLoopback(t, "target")
	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			conn.Close()
			accepted <- struct{}{}
		}
	}()
	return targetFromListener(t, ln), accepted
}

// assertNoDirectConnection fails the test if the watched target accepts a
// connection within a short grace window: relaying an upstream verdict must
// not leak an unrequested direct connection alongside it.
func assertNoDirectConnection(t *testing.T, accepted chan struct{}) {
	t.Helper()
	select {
	case <-accepted:
		t.Fatal("direct fallback occurred unexpectedly")
	case <-time.After(150 * time.Millisecond):
	}
}

// deadUpstreamAddr reserves a loopback port and closes the listener, giving
// an upstream address that refuses connections.
func deadUpstreamAddr(t *testing.T) string {
	t.Helper()
	ln := mustListenLoopback(t, "dead-upstream")
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// testTargetRefused is a fixed loopback target that refuses connections, for
// tests where the target must never be reached or any dial must fail fast.
func testTargetRefused() socks5Target {
	return socks5Target{
		atyp: socksAtypIPv4,
		ip:   netip.MustParseAddr("127.0.0.1"),
		port: 1,
		addr: "127.0.0.1:1",
	}
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
