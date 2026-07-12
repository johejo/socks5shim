package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

// TestDialDoesNotFallbackOnUpstreamAuthRejection guards the invariant that a
// credential rejection is never bypassed via a credential-less direct
// connection, including when the upstream rejects by closing the connection
// mid-subnegotiation instead of sending a STATUS byte.
func TestDialDoesNotFallbackOnUpstreamAuthRejection(t *testing.T) {
	skipIfShortNetwork(t)

	tests := []struct {
		name  string
		reply func(conn net.Conn) error // response to the RFC 1929 subnegotiation
	}{
		{
			name: "status byte rejection",
			reply: func(conn net.Conn) error {
				_, err := conn.Write([]byte{socksUserPassVersion, 0x01})
				return err
			},
		},
		{
			name:  "close without status byte",
			reply: func(conn net.Conn) error { return nil }, // returning closes the conn
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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

			handshake := func(conn net.Conn, target socks5Target) error {
				if readGreetingWithUserPass(conn) == nil {
					return fmt.Errorf("unexpected upstream greeting")
				}
				if _, err := conn.Write([]byte{socksVersion, socksMethodUserPass}); err != nil {
					return err
				}
				if _, err := readUserPassAuth(conn); err != nil {
					return err
				}
				return tt.reply(conn)
			}
			upstreamAddr, serverErr := startScriptedUpstreamHandshake(t, target, handshake, func(net.Conn) error { return nil })

			p := newTestProxy(upstreamAddr)
			conn, viaUpstream, err := p.dial(context.Background(), target, &socks5Creds{username: "user", password: "wrong"})
			if conn != nil {
				conn.Close()
				t.Fatal("expected nil conn on upstream auth rejection")
			}
			if viaUpstream {
				t.Fatal("unexpected viaUpstream=true")
			}
			if !errors.Is(err, errUpstreamAuth) {
				t.Fatalf("expected errUpstreamAuth, got: %v", err)
			}
			if p.backoff.shouldSkip(p.upstream, time.Now()) {
				t.Fatal("backoff cache must not be marked on auth rejection")
			}
			if err := <-serverErr; err != nil {
				t.Fatalf("mock upstream failed: %v", err)
			}
			select {
			case <-accepted:
				t.Fatal("direct fallback occurred despite auth rejection")
			case <-time.After(150 * time.Millisecond):
			}
		})
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
	return startDialFallbackFixtureScript(t, func(conn net.Conn) error {
		if len(connectReply) == 0 {
			// Stall until the dialer times out and closes the connection.
			io.Copy(io.Discard, conn)
			return nil
		}
		_, err := conn.Write(connectReply)
		return err
	})
}

// startDialFallbackFixtureScript is startDialFallbackFixture with a custom
// post-CONNECT upstream script.
func startDialFallbackFixtureScript(t *testing.T, script func(net.Conn) error) dialFallbackFixture {
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

	upstreamAddr, serverErr := startScriptedUpstream(t, target, script)

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

	conn, viaUpstream, err := fx.p.dial(context.Background(), fx.target, nil)
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

	conn, viaUpstream, err := fx.p.dial(context.Background(), fx.target, nil)
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

// TestDialCanceledDuringUpstreamHandshake guards the cancellation contract:
// a canceled request returns promptly and never falls back to direct, while
// the abandoned handshake rides out its own deadline in the background —
// here the upstream stalls the CONNECT reply, so the abandoned dial's
// timeout must still mark the upstream for backoff.
func TestDialCanceledDuringUpstreamHandshake(t *testing.T) {
	skipIfShortNetwork(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Cancel from the upstream script: it runs after the CONNECT request has
	// been read, so the dial is provably mid-handshake — no scheduling race.
	fx := startDialFallbackFixtureScript(t, func(conn net.Conn) error {
		cancel()
		// Stall until the abandoned dial times out and closes the connection.
		io.Copy(io.Discard, conn)
		return nil
	})
	fx.p.connectTimeout = 500 * time.Millisecond

	start := time.Now()
	conn, viaUpstream, err := fx.p.dial(ctx, fx.target, nil)
	if conn != nil {
		conn.Close()
		t.Fatal("expected nil conn on canceled dial")
	}
	if viaUpstream {
		t.Fatal("unexpected viaUpstream=true")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	// Returning well within connectTimeout (500ms) proves dial detached from
	// the stalled handshake instead of waiting it out.
	if elapsed := time.Since(start); elapsed >= 250*time.Millisecond {
		t.Fatalf("dial did not return promptly after cancel: %v", elapsed)
	}
	if err := <-fx.serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !fx.p.backoff.shouldSkip(fx.p.upstream, time.Now()) {
		if time.Now().After(deadline) {
			t.Fatal("abandoned handshake's timeout did not mark the upstream for backoff")
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case <-fx.accepted:
		t.Fatal("direct fallback occurred despite cancellation")
	case <-time.After(150 * time.Millisecond):
	}
}

// TestDialCanceledDuringAuthDoesNotMarkBackoff pins the fail-closed side of
// abandoned-handshake settling: an auth-stage failure resolved after the
// requester canceled must not mark backoff, mirroring the attended path.
func TestDialCanceledDuringAuthDoesNotMarkBackoff(t *testing.T) {
	skipIfShortNetwork(t)

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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Select user/pass, read the subnegotiation, then cancel and stall: the
	// abandoned dial times out inside authUpstream, an errUpstreamAuth path.
	handshake := func(conn net.Conn, target socks5Target) error {
		greeting := make([]byte, socksGreetingHeaderLen+2)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			return err
		}
		if _, err := conn.Write([]byte{socksVersion, socksMethodUserPass}); err != nil {
			return err
		}
		if _, err := readUserPassAuth(conn); err != nil {
			return err
		}
		cancel()
		io.Copy(io.Discard, conn)
		return nil
	}
	upstreamAddr, serverErr := startScriptedUpstreamHandshake(t, target, handshake, func(net.Conn) error { return nil })

	p := newTestProxy(upstreamAddr)
	p.connectTimeout = 200 * time.Millisecond
	conn, viaUpstream, err := p.dial(ctx, target, &socks5Creds{username: "user", password: "pass"})
	if conn != nil {
		conn.Close()
		t.Fatal("expected nil conn on canceled dial")
	}
	if viaUpstream {
		t.Fatal("unexpected viaUpstream=true")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	// serverErr resolving means the abandoned dial closed its conn; give the
	// settle goroutine a beat, then check it did not touch the cache.
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	if p.backoff.shouldSkip(p.upstream, time.Now()) {
		t.Fatal("auth-stage failure of an abandoned dial must not mark backoff")
	}
	select {
	case <-accepted:
		t.Fatal("direct fallback occurred despite cancellation")
	case <-time.After(150 * time.Millisecond):
	}
}

func TestDialPreCanceledContext(t *testing.T) {
	// Dead upstream: if dial did not short-circuit on the pre-canceled ctx, it
	// would launch a probe that hits connection-refused within milliseconds
	// and whose settle goroutine marks backoff. Asserting the mark stays
	// absent past that window proves no dial was attempted at all.
	p := newTestProxy("127.0.0.1:1")
	p.dialTimeout = 100 * time.Millisecond

	target := socks5Target{
		atyp: socksAtypIPv4,
		ip:   netip.MustParseAddr("127.0.0.1"),
		port: 1,
		addr: "127.0.0.1:1",
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, viaUpstream, err := p.dial(ctx, target, nil)
	if conn != nil {
		conn.Close()
		t.Fatal("expected nil conn on canceled dial")
	}
	if viaUpstream {
		t.Fatal("unexpected viaUpstream=true")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if p.backoff.shouldSkip(p.upstream, time.Now()) {
		t.Fatal("pre-canceled dial must not attempt an upstream connection")
	}
}

// TestDialCanceledDuringUpstreamSuccess covers the settle goroutine's success
// branch: when a handshake succeeds just after the caller cancels, the settle
// goroutine — not the gone caller — owns the conn and must close it and clear
// any backoff mark.
func TestDialCanceledDuringUpstreamSuccess(t *testing.T) {
	skipIfShortNetwork(t)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Cancel after the CONNECT request is read but before the (successful)
	// reply is sent, then sleep so dial's select provably takes the Done arm
	// before the result can reach the channel.
	fx := startDialFallbackFixtureScript(t, func(conn net.Conn) error {
		cancel()
		time.Sleep(50 * time.Millisecond)
		reply := []byte{socksVersion, socksRepSucceeded, socksRSV, socksAtypIPv4, 0, 0, 0, 0, 0, 0}
		if _, err := conn.Write(reply); err != nil {
			return err
		}
		// The success path cleared the deadline, so this only returns once
		// the settle goroutine closes the abandoned conn.
		io.Copy(io.Discard, conn)
		return nil
	})

	conn, viaUpstream, err := fx.p.dial(ctx, fx.target, nil)
	if conn != nil {
		conn.Close()
		t.Fatal("expected nil conn: the settle goroutine owns a detached success")
	}
	if viaUpstream {
		t.Fatal("unexpected viaUpstream=true")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
	}
	select {
	case err := <-fx.serverErr:
		if err != nil {
			t.Fatalf("mock upstream failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("abandoned successful dial's conn was not closed by settle")
	}
	if fx.p.backoff.shouldSkip(fx.p.upstream, time.Now()) {
		t.Fatal("successful settle must leave backoff clear")
	}
}

func TestDialDirectHonorsContext(t *testing.T) {
	skipIfShortNetwork(t)

	targetLn := mustListenLoopback(t, "target")
	target := targetFromListener(t, targetLn)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	conn, _, err := dialDirect(ctx, target)
	if conn != nil {
		conn.Close()
		t.Fatal("expected nil conn on canceled direct dial")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got: %v", err)
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

	_, _, _ = p.dial(context.Background(), target, nil)
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
