package main

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

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
