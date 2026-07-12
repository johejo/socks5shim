package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestHandleRejectsGreetingWithoutNoAuthMethod(t *testing.T) {
	tests := []struct {
		name    string
		methods []byte
	}{
		{name: "no-auth not offered", methods: []byte{0x02}},
		{name: "zero methods", methods: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := startHandleSession(t, newTestProxy("127.0.0.1:9"))
			writeGreeting(t, client, tt.methods...)

			resp := readN(t, client, 2)
			if !bytes.Equal(resp, []byte{socksVersion, socksMethodNoAcceptable}) {
				t.Fatalf("unexpected auth response: %x", resp)
			}
		})
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
		_, err := conn.Write([]byte{socksVersion, socksRepHostUnreachable, socksRSV, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
		return err
	})

	client, _ := startHandleSession(t, newTestProxy(upstreamAddr))
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
}

func TestHandleReturnsUpstreamRepToClient(t *testing.T) {
	skipIfShortNetwork(t)

	const rep = 0x02 // policy denial, never fallback-eligible

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
		_, err := conn.Write([]byte{socksVersion, rep, socksRSV, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
		return err
	})

	client, _ := startHandleSession(t, newTestProxy(upstreamAddr))
	performClientNoAuthHandshake(t, client)

	if _, err := client.Write(buildConnectRequest(target)); err != nil {
		t.Fatalf("Write CONNECT request: %v", err)
	}
	reply := readN(t, client, 10)
	if reply[1] != rep {
		t.Fatalf("unexpected rep code: 0x%02x, want 0x%02x", reply[1], rep)
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
