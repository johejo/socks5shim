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
	"sync"
	"syscall"
	"testing"
	"time"
)

const testIOTimeout = 2 * time.Second

// unreachableTargetAddr is a request target for tests where the handler
// rejects the headers before dialing, so no listener is needed. If a
// regression makes the handler dial first, the refused connection turns
// into a 502 and the status assertion fails.
const unreachableTargetAddr = "127.0.0.1:9"

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
	client, _ := startHandleSession(t, newTestProxy("127.0.0.1:9"))
	writeGreeting(t, client, 0x02)

	resp := readN(t, client, 2)
	if !bytes.Equal(resp, []byte{socksVersion, socksMethodNoAcceptable}) {
		t.Fatalf("unexpected auth response: %x", resp)
	}
}

func TestHandleRejectsZeroMethodsGreeting(t *testing.T) {
	client, _ := startHandleSession(t, newTestProxy("127.0.0.1:9"))
	writeGreeting(t, client)

	resp := readN(t, client, 2)
	if !bytes.Equal(resp, []byte{socksVersion, socksMethodNoAcceptable}) {
		t.Fatalf("unexpected auth response: %x", resp)
	}
}

func TestHandleRejectsInvalidConnectHeader(t *testing.T) {
	client, _ := startHandleSession(t, newTestProxy("127.0.0.1:9"))
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
	client, _ := startHandleSession(t, newTestProxy("127.0.0.1:9"))
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
	p := newTestProxy("127.0.0.1:9")
	p.clientReadTimeout = 50 * time.Millisecond
	client, done := startHandleSession(t, p)

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

func TestReadTargetIPv6(t *testing.T) {
	ip := netip.MustParseAddr("2001:db8::1")
	a16 := ip.As16()
	payload := append(a16[:], 0x01, 0xbb) // 443

	tgt, err := readTarget(bytes.NewReader(payload), socksAtypIPv6)
	if err != nil {
		t.Fatalf("readTarget: %v", err)
	}
	if tgt.ip != ip {
		t.Fatalf("unexpected ip: %v", tgt.ip)
	}
	if tgt.port != 443 {
		t.Fatalf("unexpected port: %d", tgt.port)
	}
	if tgt.addr != "[2001:db8::1]:443" {
		t.Fatalf("unexpected addr: %q", tgt.addr)
	}
}

func TestBuildConnectRequest(t *testing.T) {
	// Expected bytes are written out per RFC 1928 section 4, independent of
	// the production encoder and decoder.
	tests := []struct {
		name   string
		target socks5Target
		want   []byte
	}{
		{
			name: "domain",
			target: socks5Target{
				atyp:   socksAtypDomain,
				domain: "example.com",
				port:   443,
			},
			want: append(
				append([]byte{0x05, 0x01, 0x00, 0x03, 0x0b}, "example.com"...),
				0x01, 0xbb,
			),
		},
		{
			name: "ipv4",
			target: socks5Target{
				atyp: socksAtypIPv4,
				ip:   netip.MustParseAddr("192.0.2.1"),
				port: 80,
			},
			want: []byte{0x05, 0x01, 0x00, 0x01, 192, 0, 2, 1, 0x00, 0x50},
		},
		{
			name: "ipv6",
			target: socks5Target{
				atyp: socksAtypIPv6,
				ip:   netip.MustParseAddr("2001:db8::1"),
				port: 443,
			},
			want: []byte{
				0x05, 0x01, 0x00, 0x04,
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
				0x01, 0xbb,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildConnectRequest(tt.target)
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("unexpected request:\n got %x\nwant %x", got, tt.want)
			}
		})
	}
}

func TestDrainBoundAddr(t *testing.T) {
	domain := "example.com"
	tests := []struct {
		name    string
		atyp    byte
		payload []byte
	}{
		{name: "ipv4", atyp: socksAtypIPv4, payload: []byte{127, 0, 0, 1, 0x01, 0xbb}},
		{name: "ipv6", atyp: socksAtypIPv6, payload: append(make([]byte, socksIPv6AddrLen), 0x01, 0xbb)},
		{name: "domain", atyp: socksAtypDomain, payload: append(append([]byte{byte(len(domain))}, domain...), 0x01, 0xbb)},
		{name: "empty domain", atyp: socksAtypDomain, payload: []byte{0x00, 0x01, 0xbb}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// A trailing sentinel byte must survive the drain untouched.
			r := bytes.NewReader(append(tt.payload, 0xEE))
			if err := drainBoundAddr(r, tt.atyp); err != nil {
				t.Fatalf("drainBoundAddr: %v", err)
			}
			if r.Len() != 1 {
				t.Fatalf("drained wrong byte count, %d bytes left", r.Len())
			}
		})
	}

	err := drainBoundAddr(bytes.NewReader([]byte{0}), 0x09)
	if !errors.Is(err, errUnknownReplyAddressType) {
		t.Fatalf("expected errUnknownReplyAddressType, got: %v", err)
	}
}

func TestDialUpstreamRejectsInvalidReplyHeader(t *testing.T) {
	skipIfShortNetwork(t)

	target := testTarget443()
	upstreamAddr, serverErr := startScriptedUpstream(t, target, func(conn net.Conn) error {
		// Invalid VER in upstream CONNECT reply header.
		_, err := conn.Write([]byte{0x04, socksRepSucceeded, socksRSV, socksAtypIPv4})
		return err
	})

	_, err := newTestProxy(upstreamAddr).dialUpstream(target)
	if err == nil || !errors.Is(err, errUpstreamProtocol) || !strings.Contains(err.Error(), "reply header") {
		t.Fatalf("expected upstream reply header error, got: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

func TestDialDoesNotFallbackOnUpstreamConnectFailure(t *testing.T) {
	skipIfShortNetwork(t)

	tests := []struct {
		name                   string
		rep                    byte
		fallbackGeneralFailure bool
	}{
		{name: "policy denial", rep: 0x02, fallbackGeneralFailure: false},
		{name: "policy denial with general-failure fallback enabled", rep: 0x02, fallbackGeneralFailure: true},
		{name: "general failure without opt-in", rep: socksRepGeneralFailure, fallbackGeneralFailure: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fx := startDialFallbackFixture(t, []byte{socksVersion, tt.rep, socksRSV, socksAtypIPv4})
			fx.p.fallbackGeneralFailure = tt.fallbackGeneralFailure
			fx.assertNoFallback(t, tt.rep)
			if fx.p.backoff.shouldSkip(fx.p.upstream, time.Now()) {
				t.Fatal("backoff cache must not be marked on CONNECT rep failure")
			}
		})
	}
}

func TestDialFallsBackOnUpstreamDialFailure(t *testing.T) {
	skipIfShortNetwork(t)

	tests := []struct {
		name                   string
		rep                    byte
		fallbackGeneralFailure bool
	}{
		{name: "general failure with opt-in", rep: socksRepGeneralFailure, fallbackGeneralFailure: true},
		{name: "network unreachable", rep: socksRepNetworkUnreachable},
		{name: "host unreachable", rep: socksRepHostUnreachable},
		{name: "connection refused", rep: socksRepConnectionRefused},
		{name: "ttl expired", rep: socksRepTTLExpired},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Upstream-side dial failure.
			fx := startDialFallbackFixture(t, []byte{socksVersion, tt.rep, socksRSV, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
			fx.p.fallbackGeneralFailure = tt.fallbackGeneralFailure
			fx.assertDirectFallback(t)
			if fx.p.backoff.shouldSkip(fx.p.upstream, time.Now()) {
				t.Fatal("backoff cache must not be marked on CONNECT rep failure")
			}
		})
	}
}

func TestDialFallsBackOnConnectReplyTimeout(t *testing.T) {
	skipIfShortNetwork(t)

	// Upstream completes the greeting, then never answers the CONNECT request.
	fx := startDialFallbackFixture(t, nil)
	fx.p.connectTimeout = 200 * time.Millisecond
	fx.assertDirectFallback(t)
	if !fx.p.backoff.shouldSkip(fx.p.upstream, time.Now()) {
		t.Fatal("backoff cache must be marked on CONNECT reply timeout")
	}
}

type dialFallbackFixture struct {
	p         *proxy
	target    socks5Target
	accepted  chan struct{}
	serverErr chan error
}

// startDialFallbackFixture starts a target listener that signals when it is
// dialed and a mock upstream that completes the greeting, then writes
// connectReply. An empty connectReply makes the upstream stall until the
// dialer gives up and closes the connection.
func startDialFallbackFixture(t *testing.T, connectReply []byte) dialFallbackFixture {
	t.Helper()

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

	upstreamAddr, serverErr := startScriptedUpstream(t, target, func(conn net.Conn) error {
		if len(connectReply) == 0 {
			// Stall until the dialer times out and closes the connection.
			io.Copy(io.Discard, conn)
			return nil
		}
		_, err := conn.Write(connectReply)
		return err
	})

	return dialFallbackFixture{
		p:         newTestProxy(upstreamAddr),
		target:    target,
		accepted:  accepted,
		serverErr: serverErr,
	}
}

// assertDirectFallback runs dial and checks it fell back to a direct
// connection to the target.
func (fx dialFallbackFixture) assertDirectFallback(t *testing.T) {
	t.Helper()

	conn, viaUpstream, err := fx.p.dial(fx.target)
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

// assertNoFallback runs dial and checks the upstream CONNECT failure was
// propagated instead of bypassed via a direct connection.
func (fx dialFallbackFixture) assertNoFallback(t *testing.T, wantRep byte) {
	t.Helper()

	conn, viaUpstream, err := fx.p.dial(fx.target)
	if conn != nil {
		conn.Close()
		t.Fatalf("expected nil conn on upstream CONNECT failure")
	}
	if viaUpstream {
		t.Fatalf("unexpected viaUpstream=true")
	}
	var connectErr upstreamConnectError
	if !errors.As(err, &connectErr) || connectErr.rep != wantRep {
		t.Fatalf("expected upstreamConnectError rep=0x%02x, got: %v", wantRep, err)
	}
	if err := <-fx.serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}

	select {
	case <-fx.accepted:
		t.Fatal("direct fallback occurred unexpectedly")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestDialUpstreamAllowsConnectReplySlowerThanHelloTimeout(t *testing.T) {
	skipIfShortNetwork(t)

	target := testTarget443()
	upstreamAddr, serverErr := startScriptedUpstream(t, target, func(conn net.Conn) error {
		// Reply well after helloTimeout but within connectTimeout.
		time.Sleep(600 * time.Millisecond)
		_, err := conn.Write([]byte{socksVersion, socksRepSucceeded, socksRSV, socksAtypIPv4, 127, 0, 0, 1, 0x12, 0x34})
		return err
	})

	p := newTestProxy(upstreamAddr)
	p.dialTimeout = 200 * time.Millisecond
	p.connectTimeout = 5 * time.Second
	conn, err := p.dialUpstream(target)
	if err != nil {
		t.Fatalf("dialUpstream: %v", err)
	}
	conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

func TestDialUpstreamDrainsDomainBoundAddr(t *testing.T) {
	skipIfShortNetwork(t)

	target := testTarget443()
	upstreamAddr, serverErr := startScriptedUpstream(t, target, func(conn net.Conn) error {
		// Reply with a domain-typed BND.ADDR, immediately followed by relay
		// data. If drainBoundAddr consumes the wrong byte count, the client
		// reads garbage instead of "pong".
		domain := "proxy.example.com"
		reply := []byte{socksVersion, socksRepSucceeded, socksRSV, socksAtypDomain, byte(len(domain))}
		reply = append(reply, domain...)
		reply = append(reply, 0x04, 0x38) // 1080
		reply = append(reply, "pong"...)
		_, err := conn.Write(reply)
		return err
	})

	conn, err := newTestProxy(upstreamAddr).dialUpstream(target)
	if err != nil {
		t.Fatalf("dialUpstream: %v", err)
	}
	defer conn.Close()

	setDeadline(t, conn, testIOTimeout)
	if got := string(readN(t, conn, 4)); got != "pong" {
		t.Fatalf("unexpected relay data after domain bound addr: %q", got)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

func TestHandleSuccessfulConnectAndRelayViaUpstream(t *testing.T) {
	skipIfShortNetwork(t)

	target := testTarget443()
	upstreamAddr, serverErr := startScriptedUpstream(t, target, func(conn net.Conn) error {
		reply := []byte{socksVersion, socksRepSucceeded, socksRSV, socksAtypIPv4, 127, 0, 0, 1, 0x12, 0x34}
		if _, err := conn.Write(reply); err != nil {
			return err
		}

		payload := make([]byte, 4)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return err
		}
		if string(payload) != "ping" {
			return fmt.Errorf("unexpected relay payload: %q", payload)
		}
		_, err := conn.Write([]byte("pong"))
		return err
	})

	client, _ := startHandleSession(t, newTestProxy(upstreamAddr))
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

func TestHandleFallsBackToDirectOnUpstreamConnectFailure(t *testing.T) {
	skipIfShortNetwork(t)

	tests := []struct {
		name                   string
		rep                    byte
		fallbackGeneralFailure bool
	}{
		{name: "host unreachable", rep: socksRepHostUnreachable, fallbackGeneralFailure: false},
		{name: "general failure with opt-in", rep: socksRepGeneralFailure, fallbackGeneralFailure: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Target answers "pong" to "ping" so the direct relay is observable.
			targetLn := mustListenLoopback(t, "target")
			go func() {
				conn, err := targetLn.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				payload := make([]byte, 4)
				if _, err := io.ReadFull(conn, payload); err != nil {
					return
				}
				if string(payload) == "ping" {
					conn.Write([]byte("pong"))
				}
			}()
			target := targetFromListener(t, targetLn)

			upstreamAddr, serverErr := startScriptedUpstream(t, target, func(conn net.Conn) error {
				// Fallback-eligible failure: handle() must retry direct.
				_, err := conn.Write([]byte{socksVersion, tt.rep, socksRSV, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
				return err
			})

			p := newTestProxy(upstreamAddr)
			p.fallbackGeneralFailure = tt.fallbackGeneralFailure
			client, _ := startHandleSession(t, p)
			performClientNoAuthHandshake(t, client)

			if _, err := client.Write(buildConnectRequest(target)); err != nil {
				t.Fatalf("Write CONNECT request: %v", err)
			}
			reply := readN(t, client, 10)
			if reply[1] != socksRepSucceeded {
				t.Fatalf("unexpected rep code: 0x%02x", reply[1])
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("mock upstream failed: %v", err)
			}

			if _, err := client.Write([]byte("ping")); err != nil {
				t.Fatalf("Write relay payload: %v", err)
			}
			if got := string(readN(t, client, 4)); got != "pong" {
				t.Fatalf("unexpected relay response: %q", got)
			}
		})
	}
}

func TestHandleReturnsUpstreamRepToClient(t *testing.T) {
	skipIfShortNetwork(t)

	tests := []struct {
		name string
		rep  byte
	}{
		// Non-eligible failures must be forwarded to the client verbatim.
		{name: "policy denial", rep: 0x02},
		{name: "general failure without opt-in", rep: socksRepGeneralFailure},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			upstreamAddr, serverErr := startScriptedUpstream(t, target, func(conn net.Conn) error {
				_, err := conn.Write([]byte{socksVersion, tt.rep, socksRSV, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
				return err
			})

			client, _ := startHandleSession(t, newTestProxy(upstreamAddr))
			performClientNoAuthHandshake(t, client)

			if _, err := client.Write(buildConnectRequest(target)); err != nil {
				t.Fatalf("Write CONNECT request: %v", err)
			}
			reply := readN(t, client, 10)
			if reply[1] != tt.rep {
				t.Fatalf("unexpected rep code: 0x%02x, want 0x%02x", reply[1], tt.rep)
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("mock upstream failed: %v", err)
			}

			select {
			case <-accepted:
				t.Fatal("direct fallback occurred unexpectedly")
			case <-time.After(150 * time.Millisecond):
			}
		})
	}
}

func TestDialMarksUnavailableBackoff(t *testing.T) {
	p := newTestProxy("127.0.0.1:1")
	p.dialTimeout = 100 * time.Millisecond

	target := socks5Target{
		atyp: socksAtypIPv4,
		ip:   netip.MustParseAddr("127.0.0.1"),
		port: 1,
		addr: "127.0.0.1:1",
	}

	_, _, _ = p.dial(target)
	if !p.backoff.shouldSkip(p.upstream, time.Now()) {
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

// startHandleSession runs p.handle on one end of a pipe and returns the
// other end plus a channel closed when the handler exits.
func startHandleSession(t *testing.T, p *proxy) (net.Conn, chan struct{}) {
	t.Helper()
	client, server := testClientServer(t)
	done := make(chan struct{})
	go func() {
		p.handle(server)
		close(done)
	}()
	setDeadline(t, client, testIOTimeout)
	t.Cleanup(func() {
		client.Close()
		waitDone(t, done)
	})
	return client, done
}

// startHandleHTTPSession is startHandleSession for the HTTP handler.
func startHandleHTTPSession(t *testing.T, p *proxy) (net.Conn, chan struct{}) {
	t.Helper()
	client, server := testClientServer(t)
	done := make(chan struct{})
	go func() {
		p.handleHTTP(server)
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

// startScriptedUpstream starts a mock SOCKS5 upstream that accepts one
// connection, verifies the greeting and CONNECT request for target, then
// runs script on the connection. The returned channel receives the script's
// result (or the earlier accept/handshake error).
func startScriptedUpstream(t *testing.T, target socks5Target, script func(net.Conn) error) (addr string, serverErr chan error) {
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

		if err := performUpstreamNoAuthHandshake(conn, target); err != nil {
			serverErr <- err
			return
		}
		serverErr <- script(conn)
	}()
	return ln.Addr().String(), serverErr
}

// testTarget443 is an arbitrary fixed CONNECT target for tests whose mock
// upstream never actually dials it.
func testTarget443() socks5Target {
	return socks5Target{
		atyp: socksAtypIPv4,
		ip:   netip.MustParseAddr("1.2.3.4"),
		port: 443,
		addr: "1.2.3.4:443",
	}
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

func TestHandleHTTPPlainStripsProxyHeaders(t *testing.T) {
	skipIfShortNetwork(t)

	targetAddr := startHeaderEchoTarget(t, func(req *http.Request) string {
		return fmt.Sprintf("proxy-connection=%q proxy-authorization=%q",
			req.Header.Get("Proxy-Connection"), req.Header.Get("Proxy-Authorization"))
	})

	proxyAddr := startHTTPProxyStack(t, "")
	conn := dialHTTPProxy(t, proxyAddr)
	fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\nConnection: close\r\n\r\n", targetAddr, targetAddr)

	body := readProxyResponseBody(t, conn)
	if !strings.Contains(body, `proxy-connection=""`) {
		t.Fatalf("Proxy-Connection was not stripped: %s", body)
	}
	if !strings.Contains(body, `proxy-authorization=""`) {
		t.Fatalf("Proxy-Authorization was not stripped: %s", body)
	}
}

func TestHandleHTTPPlainStripsConnectionNominatedHeaders(t *testing.T) {
	skipIfShortNetwork(t)

	targetAddr := startHeaderEchoTarget(t, func(req *http.Request) string {
		return fmt.Sprintf("x-session-token=%q x-other=%q",
			req.Header.Get("X-Session-Token"), req.Header.Get("X-Other"))
	})

	proxyAddr := startHTTPProxyStack(t, "")
	conn := dialHTTPProxy(t, proxyAddr)
	// The nominated header precedes the Connection header that names it,
	// so streaming forwarding would leak it.
	fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nX-Session-Token: secret\r\nX-Other: keep\r\nConnection: X-Session-Token, close\r\n\r\n", targetAddr, targetAddr)

	body := readProxyResponseBody(t, conn)
	if !strings.Contains(body, `x-session-token=""`) {
		t.Fatalf("Connection-nominated header was not stripped: %s", body)
	}
	if !strings.Contains(body, `x-other="keep"`) {
		t.Fatalf("unrelated header was stripped: %s", body)
	}
}

func TestHandleHTTPPlainStripsWellKnownHopByHopHeaders(t *testing.T) {
	skipIfShortNetwork(t)

	targetAddr := startHeaderEchoTarget(t, func(req *http.Request) string {
		return fmt.Sprintf("upgrade=%q te=%q proxy-authenticate=%q trailer=%q",
			req.Header.Get("Upgrade"), req.Header.Get("TE"), req.Header.Get("Proxy-Authenticate"), req.Header.Get("Trailer"))
	})

	proxyAddr := startHTTPProxyStack(t, "")
	conn := dialHTTPProxy(t, proxyAddr)
	fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nTE: trailers\r\nProxy-Authenticate: Basic\r\nTrailer: Expires\r\nConnection: close\r\n\r\n", targetAddr, targetAddr)

	body := readProxyResponseBody(t, conn)
	for _, want := range []string{`upgrade=""`, `te=""`, `proxy-authenticate=""`, `trailer=""`} {
		if !strings.Contains(body, want) {
			t.Fatalf("hop-by-hop header was not stripped, want %s in: %s", want, body)
		}
	}
}

func TestHandleHTTPPlainForwardsTransferEncoding(t *testing.T) {
	skipIfShortNetwork(t)

	// Transfer-Encoding describes body framing and the body is relayed as
	// raw bytes, so stripping it would desync the origin's body parsing.
	targetAddr := startHeaderEchoTarget(t, func(req *http.Request) string {
		if _, err := io.ReadAll(req.Body); err != nil {
			return fmt.Sprintf("body error: %v", err)
		}
		return fmt.Sprintf("transfer-encoding=%q", strings.Join(req.TransferEncoding, ","))
	})

	proxyAddr := startHTTPProxyStack(t, "")
	conn := dialHTTPProxy(t, proxyAddr)
	fmt.Fprintf(conn, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nhi\r\n0\r\n\r\n", targetAddr, targetAddr)

	body := readProxyResponseBody(t, conn)
	if !strings.Contains(body, `transfer-encoding="chunked"`) {
		t.Fatalf("Transfer-Encoding was stripped: %s", body)
	}
}

func TestHandleHTTPPlainRejectsOversizedHeaders(t *testing.T) {
	skipIfShortNetwork(t)

	proxyAddr := startHTTPProxyStack(t, "")
	conn := dialHTTPProxy(t, proxyAddr)

	// Write concurrently: it blocks once the handler's buffer fills,
	// leaving this goroutine free to read the 431.
	targetAddr := unreachableTargetAddr
	var payload bytes.Buffer
	fmt.Fprintf(&payload, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	pad := strings.Repeat("a", 4<<10)
	for i := 0; payload.Len() <= maxHTTPHeaderBytes; i++ {
		fmt.Fprintf(&payload, "X-Pad-%d: %s\r\n", i, pad)
	}
	payload.WriteString("\r\n")
	wrote := make(chan struct{})
	go func() {
		defer close(wrote)
		conn.Write(payload.Bytes())
	}()

	if status := readProxyStatus(t, conn); status != 431 {
		t.Fatalf("unexpected status: %d", status)
	}
	<-wrote
}

func TestSplitHeaderLine(t *testing.T) {
	for _, tc := range []struct {
		line        string
		name, value string
		ok          bool
	}{
		{"Host: example.com\r\n", "host", " example.com", true},
		{"X-A:v\r\n", "x-a", "v", true},
		{"X-A: v: w\r\n", "x-a", " v: w", true},
		{"X-A : v\r\n", "", "", false},
		{" folded\r\n", "", "", false},
		{"\tfolded: v\r\n", "", "", false},
		{"no-colon-line\r\n", "", "", false},
		{": v\r\n", "", "", false},
		{"X@A: v\r\n", "", "", false},
		{"X\x00A: v\r\n", "", "", false},
		{"X-A: a\rEvil: b\r\n", "", "", false},
		{"X-A: a\x00b\r\n", "", "", false},
		{"X-A: a\x7fb\r\n", "", "", false},
	} {
		name, value, ok := splitHeaderLine(tc.line)
		if name != tc.name || value != tc.value || ok != tc.ok {
			t.Errorf("splitHeaderLine(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.line, name, value, ok, tc.name, tc.value, tc.ok)
		}
	}
}

func TestHandleHTTPPlainRejectsMalformedHeaders(t *testing.T) {
	skipIfShortNetwork(t)

	for _, tc := range []struct {
		name   string
		header string
	}{
		{"obs-fold continuation", "X-A: first\r\n second\r\n"},
		{"space before colon", "X-A : v\r\n"},
		{"no colon", "garbage\r\n"},
		{"empty name", ": v\r\n"},
		{"non-token name", "X@A: v\r\n"},
		{"bare CR in value", "X-A: a\rEvil: b\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targetAddr := unreachableTargetAddr
			proxyAddr := startHTTPProxyStack(t, "")
			conn := dialHTTPProxy(t, proxyAddr)

			// No terminating blank line: the handler rejects at the bad
			// header, and unread bytes would risk a RST eating the reply.
			fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n%s", targetAddr, targetAddr, tc.header)

			if status := readProxyStatus(t, conn); status != 400 {
				t.Fatalf("unexpected status: %d", status)
			}
		})
	}
}

func TestHandleHTTPPlainRejectsTooManyHeaderLines(t *testing.T) {
	skipIfShortNetwork(t)

	targetAddr := unreachableTargetAddr
	proxyAddr := startHTTPProxyStack(t, "")
	conn := dialHTTPProxy(t, proxyAddr)

	// Host plus maxHTTPHeaderLines more lines: the limit trips on the
	// last one, so the handler consumes every byte sent (no RST risk).
	var payload bytes.Buffer
	fmt.Fprintf(&payload, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	for i := range maxHTTPHeaderLines {
		fmt.Fprintf(&payload, "X-N-%d: v\r\n", i)
	}
	if _, err := conn.Write(payload.Bytes()); err != nil {
		t.Fatalf("write: %v", err)
	}

	if status := readProxyStatus(t, conn); status != 431 {
		t.Fatalf("unexpected status: %d", status)
	}
}

func TestHandleHTTPConnectRejectsTooManyHeaderLines(t *testing.T) {
	client, done := startHandleHTTPSession(t, newTestProxy("127.0.0.1:9"))

	var payload bytes.Buffer
	payload.WriteString("CONNECT example.com:443 HTTP/1.1\r\n")
	for i := 0; i <= maxHTTPHeaderLines; i++ {
		fmt.Fprintf(&payload, "X-N-%d: v\r\n", i)
	}
	if _, err := client.Write(payload.Bytes()); err != nil {
		t.Fatalf("write: %v", err)
	}

	if status := readProxyStatus(t, client); status != 431 {
		t.Fatalf("unexpected status: %d", status)
	}
	waitDone(t, done)
}

func TestHandleHTTPPlainForcesConnectionClose(t *testing.T) {
	skipIfShortNetwork(t)

	connHeader := make(chan string, 1)
	keepAliveHeader := make(chan string, 1)
	targetAddr := startKeepAliveTarget(t, func(req *http.Request) string {
		select {
		case connHeader <- req.Header.Get("Connection"):
		default:
		}
		select {
		case keepAliveHeader <- req.Header.Get("Keep-Alive"):
		default:
		}
		return "OK"
	})

	proxyAddr := startHTTPProxyStack(t, "")
	conn := dialHTTPProxy(t, proxyAddr)

	fmt.Fprintf(conn, "GET http://%s/ HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5, max=100\r\n\r\n", targetAddr, targetAddr)

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("read body: %v", err)
	}
	resp.Body.Close()

	if got := <-connHeader; got != "close" {
		t.Fatalf("target received Connection: %q, want %q", got, "close")
	}
	if got := <-keepAliveHeader; got != "" {
		t.Fatalf("Keep-Alive was not stripped: %q", got)
	}

	// The proxy must close the client connection after the response so a
	// second request cannot be misrouted to the first target.
	setDeadline(t, conn, testIOTimeout)
	if _, err := br.ReadByte(); err != io.EOF {
		t.Fatalf("expected EOF after response, got %v", err)
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

func TestHandleHTTPRejectsInvalidProto(t *testing.T) {
	client, done := startHandleHTTPSession(t, newTestProxy("127.0.0.1:9"))

	// Send a request with a bogus protocol version.
	fmt.Fprintf(client, "GET / HTTP/2.0\r\nHost: example.com\r\n\r\n")

	// The handler should close the connection because proto is not HTTP/1.0 or HTTP/1.1.
	waitDone(t, done)
}

func TestHandleHTTPRejectsNonTokenMethod(t *testing.T) {
	client, done := startHandleHTTPSession(t, newTestProxy("127.0.0.1:9"))

	// Send a request whose method is not a valid token.
	fmt.Fprintf(client, "GE\x00T / HTTP/1.1\r\nHost: example.com\r\n\r\n")

	// The handler should close the connection because the method is not a token.
	waitDone(t, done)
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
			client, done := startHandleHTTPSession(t, newTestProxy("127.0.0.1:9"))

			fmt.Fprintf(client, "CONNECT %s HTTP/1.1\r\nHost: example.com\r\n\r\n", tc.uri)

			if status := readProxyStatus(t, client); status != 400 {
				t.Fatalf("unexpected status: %d", status)
			}
			waitDone(t, done)
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
			client, done := startHandleHTTPSession(t, newTestProxy("127.0.0.1:9"))

			fmt.Fprintf(client, "GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", tc.uri)

			if status := readProxyStatus(t, client); status != 400 {
				t.Fatalf("unexpected status: %d", status)
			}
			waitDone(t, done)
		})
	}
}

func TestHandleHTTPRejectsOversizedLine(t *testing.T) {
	for _, tc := range []struct {
		name   string
		prefix string
	}{
		{"request line", "GET /"},
		{"connect header", "CONNECT example.com:443 HTTP/1.1\r\nX-Pad: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, done := startHandleHTTPSession(t, newTestProxy("127.0.0.1:9"))

			// Write concurrently: it blocks once the handler's buffer fills,
			// leaving this goroutine free to read the 431.
			payload := append([]byte(tc.prefix), bytes.Repeat([]byte("a"), maxHTTPLineLength+1)...)
			wrote := make(chan struct{})
			go func() {
				defer close(wrote)
				client.Write(payload)
			}()

			if status := readProxyStatus(t, client); status != 431 {
				t.Fatalf("unexpected status: %d", status)
			}
			waitDone(t, done)
			<-wrote
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

// readProxyResponseBody reads one HTTP response from conn and returns its body.
func readProxyResponseBody(t *testing.T, conn net.Conn) string {
	t.Helper()
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
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
	go func() {
		for {
			conn, err := httpLn.Accept()
			if err != nil {
				return
			}
			go p.handleHTTP(conn)
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

	relay(conn, remote)
}

type acceptResult struct {
	conn net.Conn
	err  error
}

// scriptedListener returns seq in order, then net.ErrClosed.
type scriptedListener struct {
	mu    sync.Mutex
	seq   []acceptResult
	next  int
	times []time.Time
}

func (l *scriptedListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.times = append(l.times, time.Now())
	if l.next >= len(l.seq) {
		return nil, net.ErrClosed
	}
	r := l.seq[l.next]
	l.next++
	return r.conn, r.err
}

func (l *scriptedListener) Close() error   { return nil }
func (l *scriptedListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func (l *scriptedListener) acceptTimes() []time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]time.Time(nil), l.times...)
}

func runAcceptLoop(t *testing.T, ln net.Listener, handler func(net.Conn)) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		acceptLoop(ln, "test", handler)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(testIOTimeout):
		t.Fatal("acceptLoop did not return on net.ErrClosed")
	}
}

func TestAcceptLoopDispatchesAfterTransientErrors(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	ln := &scriptedListener{seq: []acceptResult{
		{err: errors.New("accept tcp: too many open files")},
		{err: errors.New("accept tcp: too many open files")},
		{conn: c1},
	}}

	handled := make(chan net.Conn, 1)
	runAcceptLoop(t, ln, func(conn net.Conn) { handled <- conn })

	select {
	case conn := <-handled:
		if conn != c1 {
			t.Fatalf("handle received unexpected conn: %v", conn)
		}
	case <-time.After(testIOTimeout):
		t.Fatal("handle was not called after transient accept errors")
	}
}

func TestAcceptLoopReturnsOnErrClosedWithoutHandling(t *testing.T) {
	ln := &scriptedListener{}
	runAcceptLoop(t, ln, func(conn net.Conn) {
		t.Error("handle should not be called")
	})
	if got := len(ln.acceptTimes()); got != 1 {
		t.Fatalf("Accept called %d times, want 1", got)
	}
}

func TestAcceptLoopBacksOffBetweenErrors(t *testing.T) {
	ln := &scriptedListener{seq: []acceptResult{
		{err: errors.New("accept tcp: too many open files")},
		{err: errors.New("accept tcp: too many open files")},
		{err: errors.New("accept tcp: too many open files")},
	}}

	runAcceptLoop(t, ln, func(net.Conn) {})

	times := ln.acceptTimes()
	if len(times) != 4 {
		t.Fatalf("Accept called %d times, want 4", len(times))
	}
	// time.Sleep waits at least the requested duration, so only lower bounds
	// are safe to assert.
	for i, want := range []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond} {
		if gap := times[i+1].Sub(times[i]); gap < want {
			t.Errorf("gap after error %d = %s, want >= %s", i+1, gap, want)
		}
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
