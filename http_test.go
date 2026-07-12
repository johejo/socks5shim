package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHandleHTTPConnect(t *testing.T) {
	skipIfShortNetwork(t)

	targetAddr := startEchoTarget(t)

	// Connect to the HTTP proxy and send a CONNECT request.
	proxyAddr := startHTTPProxyStack(t, targetAddr)
	conn := dialHTTPProxy(t, proxyAddr)

	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)

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

// TestHandleHTTPConnectClientDisconnectUnblocksHandler pins the payoff of
// threading r.Context() into dial, including the stdlib guarantee it rests
// on (the Server cancels the request context when the client disconnects):
// a CONNECT client that gives up mid-dial frees the handler promptly instead
// of holding it for the whole connect budget.
func TestHandleHTTPConnectClientDisconnectUnblocksHandler(t *testing.T) {
	skipIfShortNetwork(t)

	targetLn := mustListenLoopback(t, "target")
	target := targetFromListener(t, targetLn)

	// Upstream completes the greeting, signals that the CONNECT request
	// arrived, then stalls the reply.
	dialing := make(chan struct{})
	upstreamAddr, _ := startScriptedUpstream(t, target, func(conn net.Conn) error {
		close(dialing)
		io.Copy(io.Discard, conn)
		return nil
	})

	p := newTestProxy(upstreamAddr)
	// A budget far beyond the assertion window, so a prompt handler exit can
	// only come from cancellation, not from the dial timing out.
	p.connectTimeout = 5 * time.Second

	client, done := startHandleHTTPSession(t, p)
	fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target.addr, target.addr)

	select {
	case <-dialing:
	case <-time.After(testIOTimeout):
		t.Fatal("upstream never saw the CONNECT request")
	}
	client.Close()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("handler still blocked in dial after client disconnect")
	}
}

func TestHandleHTTPPlainGET(t *testing.T) {
	skipIfShortNetwork(t)

	targetAddr := startHeaderEchoTarget(t, func(req *http.Request) string {
		if req.URL.Path != "/test" {
			return "unexpected path: " + req.URL.Path
		}
		return "OK"
	})

	// Send a plain HTTP GET through the proxy.
	proxyAddr := startHTTPProxyStack(t, "")
	conn := dialHTTPProxy(t, proxyAddr)

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

func TestHandleHTTPRejectsLowercaseConnect(t *testing.T) {
	client, _ := startHandleHTTPSession(t, newTestProxy("127.0.0.1:9"))

	// Methods are case-sensitive (RFC 9110 §9.1): lowercase connect is
	// not CONNECT, and its authority-form target is not absolute-form
	// http, so the plain path rejects it.
	fmt.Fprintf(client, "connect example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n")

	if status := readProxyStatus(t, client); status != 400 {
		t.Fatalf("unexpected status: %d", status)
	}
}

func TestHandleHTTPPlainSecondRequestNotMisrouted(t *testing.T) {
	skipIfShortNetwork(t)

	// Two targets that honor keep-alive, each identified by its response body.
	targetA := startKeepAliveTarget(t, func(*http.Request) string { return "target-a" })
	targetB := startKeepAliveTarget(t, func(*http.Request) string { return "target-b" })

	proxyAddr := startHTTPProxyStack(t, "")
	conn := dialHTTPProxy(t, proxyAddr)
	br := bufio.NewReader(conn)

	sendGet := func(addr string) {
		fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", addr, addr)
	}
	readBody := func(which string) (string, error) {
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read %s response body: %v", which, err)
		}
		return string(body), nil
	}

	sendGet(targetA)
	body, err := readBody("first")
	if err != nil {
		t.Fatalf("read first response: %v", err)
	}
	if body != "target-a" {
		t.Fatalf("first response body = %q, want %q", body, "target-a")
	}

	// Second request on the same client connection targets B. The invariant:
	// it must never be answered by A. Acceptable outcomes are a connection
	// error (the proxy closed the connection after the first response) or a
	// response from B (an implementation that routes each request).
	setDeadline(t, conn, testIOTimeout)
	sendGet(targetB)
	body, err = readBody("second")
	if err != nil {
		t.Logf("proxy closed the connection before a second response: %v", err)
		return
	}
	if body != "target-b" {
		t.Fatalf("second response body = %q, want %q (misrouted to the first target?)", body, "target-b")
	}
}

func TestHandleHTTPRejectsInvalidHostLength(t *testing.T) {
	for _, tc := range []struct {
		name string
		uri  string
	}{
		{"empty host", ":443"},
		{"oversized host", strings.Repeat("a", 256) + ":443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := startHandleHTTPSession(t, newTestProxy("127.0.0.1:9"))

			fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: example.com\r\n\r\n", tc.uri)

			if status := readProxyStatus(t, client); status != 400 {
				t.Fatalf("unexpected status: %d", status)
			}
		})
	}
}

func TestHandleHTTPPlainRejectsNonHTTPScheme(t *testing.T) {
	for _, tc := range []struct {
		name string
		uri  string
	}{
		{"https scheme", "https://example.com/"},
		{"ftp scheme", "ftp://example.com/"},
		{"empty scheme", "//example.com/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, _ := startHandleHTTPSession(t, newTestProxy("127.0.0.1:9"))

			fmt.Fprintf(client, "GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", tc.uri)

			if status := readProxyStatus(t, client); status != 400 {
				t.Fatalf("unexpected status: %d", status)
			}
		})
	}
}

func TestHandleHTTPConnectFallsBackToDirect(t *testing.T) {
	skipIfShortNetwork(t)

	targetAddr := startEchoTarget(t)

	client := dialHTTPProxyWithDeadUpstream(t)

	fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)

	br := bufio.NewReader(client)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("write through tunnel: %v", err)
	}
	echoed := readN(t, br, 5)
	if string(echoed) != "hello" {
		t.Fatalf("unexpected echo: %q", echoed)
	}
}

func TestHandleHTTPPlainFallsBackToDirect(t *testing.T) {
	skipIfShortNetwork(t)

	targetAddr := startHeaderEchoTarget(t, func(*http.Request) string { return "OK" })

	client := dialHTTPProxyWithDeadUpstream(t)

	fmt.Fprintf(client, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetAddr, targetAddr)

	br := bufio.NewReader(client)
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

// startHandleHTTPSession serves one in-memory connection with the proxy's
// HTTP server and returns the client end plus a channel closed when the
// server tears the connection down (or hands it off via Hijack).
func startHandleHTTPSession(t *testing.T, p *proxy) (net.Conn, chan struct{}) {
	t.Helper()
	client, server := testClientServer(t)
	done := make(chan struct{})
	var once sync.Once
	srv := p.newHTTPServer()
	srv.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateClosed || state == http.StateHijacked {
			once.Do(func() { close(done) })
		}
	}
	go srv.Serve(newOneShotListener(server))
	setDeadline(t, client, testIOTimeout)
	t.Cleanup(func() {
		client.Close()
		srv.Close()
		waitDone(t, done)
	})
	return client, done
}

// oneShotListener yields a single pre-made connection to a Server, then
// blocks until closed.
type oneShotListener struct {
	mu   sync.Mutex
	conn net.Conn
	addr net.Addr
	done chan struct{}
}

func newOneShotListener(conn net.Conn) *oneShotListener {
	return &oneShotListener{conn: conn, addr: conn.LocalAddr(), done: make(chan struct{})}
}

func (l *oneShotListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	conn := l.conn
	l.conn = nil
	l.mu.Unlock()
	if conn != nil {
		return conn, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneShotListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	select {
	case <-l.done:
	default:
		close(l.done)
	}
	return nil
}

func (l *oneShotListener) Addr() net.Addr { return l.addr }

// dialHTTPProxyWithDeadUpstream starts handleHTTP with an upstream address
// that refuses connections, forcing the direct fallback path.
func dialHTTPProxyWithDeadUpstream(t *testing.T) net.Conn {
	t.Helper()

	deadLn := mustListenLoopback(t, "dead-upstream")
	deadAddr := deadLn.Addr().String()
	deadLn.Close()

	client, _ := startHandleHTTPSession(t, newTestProxy(deadAddr))
	return client
}

// startEchoTarget starts a TCP server that accepts one connection and
// echoes everything back, and returns its address.
func startEchoTarget(t *testing.T) string {
	t.Helper()
	ln := mustListenLoopback(t, "target")
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		io.Copy(conn, conn)
	}()
	return ln.Addr().String()
}

// startKeepAliveTarget starts an HTTP target that serves requests on the
// same connection until one asks for Connection: close, answering each with
// the body built by respond, and returns its address.
func startKeepAliveTarget(t *testing.T, respond func(*http.Request) string) string {
	t.Helper()
	ln := mustListenLoopback(t, "target")
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					req, err := http.ReadRequest(br)
					if err != nil {
						return
					}
					body := respond(req)
					fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body)
					if req.Close {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// startHeaderEchoTarget starts an HTTP target that answers each request
// with a body built by describe, and returns its address.
func startHeaderEchoTarget(t *testing.T, describe func(*http.Request) string) string {
	t.Helper()
	ln := mustListenLoopback(t, "target")
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				body := describe(req)
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// readProxyStatus reads one HTTP response from conn and returns its status code.
func readProxyStatus(t *testing.T, conn net.Conn) int {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	resp.Body.Close()
	return resp.StatusCode
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

	p := newTestProxy(upstreamLn.Addr().String())
	httpLn := mustListenLoopback(t, "http-proxy")
	srv := p.newHTTPServer()
	go srv.Serve(httpLn)
	t.Cleanup(func() { srv.Close() })
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

	relay(conn, remote)
}
