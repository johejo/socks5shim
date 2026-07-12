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

func TestHandleRejectsGreetingWithoutAcceptableMethod(t *testing.T) {
	tests := []struct {
		name    string
		methods []byte
	}{
		{name: "unsupported method only", methods: []byte{0x01}}, // GSSAPI
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

func TestHandleSelectsUserPassMethod(t *testing.T) {
	tests := []struct {
		name    string
		methods []byte
	}{
		{name: "user-pass only", methods: []byte{socksMethodUserPass}},
		{name: "preferred over no-auth", methods: []byte{socksMethodNoAuth, socksMethodUserPass}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := startHandleSession(t, newTestProxy("127.0.0.1:9"))
			writeGreeting(t, client, tt.methods...)

			resp := readN(t, client, 2)
			if !bytes.Equal(resp, []byte{socksVersion, socksMethodUserPass}) {
				t.Fatalf("unexpected auth response: %x", resp)
			}
		})
	}
}

func TestHandleClosesOnBadUserPassVersion(t *testing.T) {
	client, done := startHandleSession(t, newTestProxy("127.0.0.1:9"))
	writeGreeting(t, client, socksMethodUserPass)
	readN(t, client, 2)

	// RFC 1929 subnegotiation must start with VER=0x01; the handler rejects
	// after reading the two header bytes.
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		t.Fatalf("Write auth request: %v", err)
	}
	waitDone(t, done)
}

func TestHandleTimesOutOnStalledUserPassSubnegotiation(t *testing.T) {
	p := newTestProxy("127.0.0.1:9")
	p.clientReadTimeout = 50 * time.Millisecond
	client, done := startHandleSession(t, p)
	writeGreeting(t, client, socksMethodUserPass)
	readN(t, client, 2)

	// Announce an 8-byte username then stall; handler should exit on deadline.
	if _, err := client.Write([]byte{socksUserPassVersion, 0x08}); err != nil {
		t.Fatalf("Write partial auth request: %v", err)
	}
	waitDone(t, done)
}

func TestReadUserPassAuth(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    socks5Creds
		wantErr bool
	}{
		{
			name:    "basic",
			payload: []byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x02, 'p', 'w'},
			want:    socks5Creds{username: "user", password: "pw"},
		},
		{
			// RFC 1929 says 1-255, but the shim is lenient and forwards as-is.
			name:    "empty fields",
			payload: []byte{0x01, 0x00, 0x00},
			want:    socks5Creds{},
		},
		{
			// Boundary for the ULEN+1 read trick: 255-byte username.
			name:    "max-length username",
			payload: append(append([]byte{0x01, 0xFF}, bytes.Repeat([]byte{'x'}, 255)...), 0x01, 'p'),
			want:    socks5Creds{username: strings.Repeat("x", 255), password: "p"},
		},
		{name: "bad version", payload: []byte{0x05, 0x00, 0x00}, wantErr: true},
		{name: "truncated username", payload: []byte{0x01, 0x04, 'u'}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := readUserPassAuth(bytes.NewReader(tt.payload))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got creds %q/%q", got.username, got.password)
				}
				return
			}
			if err != nil {
				t.Fatalf("readUserPassAuth: %v", err)
			}
			if got != tt.want {
				t.Fatalf("unexpected creds: %q/%q", got.username, got.password)
			}
		})
	}
}

func TestBuildUserPassRequest(t *testing.T) {
	// Expected bytes are written out per RFC 1929 section 2, independent of
	// the production decoder.
	got := buildUserPassRequest(&socks5Creds{username: "user", password: "pw"})
	want := []byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x02, 'p', 'w'}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected request:\n got %x\nwant %x", got, want)
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

	_, err := newTestProxy(upstreamAddr).dialUpstream(target, nil)
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
	conn, err := p.dialUpstream(target, nil)
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

	conn, err := newTestProxy(upstreamAddr).dialUpstream(target, nil)
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

func TestDialUpstreamSendsCredentials(t *testing.T) {
	skipIfShortNetwork(t)

	target := testTarget443()
	upstreamAddr, serverErr := startScriptedUpstreamHandshake(t, target,
		performUpstreamUserPassHandshake("user", "pass"),
		func(conn net.Conn) error {
			_, err := conn.Write([]byte{socksVersion, socksRepSucceeded, socksRSV, socksAtypIPv4, 127, 0, 0, 1, 0x12, 0x34})
			return err
		})

	conn, err := newTestProxy(upstreamAddr).dialUpstream(target, &socks5Creds{username: "user", password: "pass"})
	if err != nil {
		t.Fatalf("dialUpstream: %v", err)
	}
	conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

func TestDialUpstreamWithCredsUpstreamPicksNoAuth(t *testing.T) {
	skipIfShortNetwork(t)

	target := testTarget443()
	handshake := func(conn net.Conn, target socks5Target) error {
		greeting := readGreetingWithUserPass(conn)
		if greeting == nil {
			return fmt.Errorf("unexpected upstream greeting")
		}
		// Upstream may pick no-auth even when credentials were offered; the
		// subnegotiation must be skipped.
		if _, err := conn.Write([]byte{socksVersion, socksMethodNoAuth}); err != nil {
			return err
		}
		return expectConnectRequest(conn, target)
	}
	upstreamAddr, serverErr := startScriptedUpstreamHandshake(t, target, handshake, func(conn net.Conn) error {
		_, err := conn.Write([]byte{socksVersion, socksRepSucceeded, socksRSV, socksAtypIPv4, 127, 0, 0, 1, 0x12, 0x34})
		return err
	})

	conn, err := newTestProxy(upstreamAddr).dialUpstream(target, &socks5Creds{username: "user", password: "pass"})
	if err != nil {
		t.Fatalf("dialUpstream: %v", err)
	}
	conn.Close()
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

func TestDialUpstreamAuthRejected(t *testing.T) {
	skipIfShortNetwork(t)

	target := testTarget443()
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
		_, err := conn.Write([]byte{socksUserPassVersion, 0x01}) // reject
		return err
	}
	upstreamAddr, serverErr := startScriptedUpstreamHandshake(t, target, handshake, func(net.Conn) error { return nil })

	_, err := newTestProxy(upstreamAddr).dialUpstream(target, &socks5Creds{username: "user", password: "wrong"})
	if !errors.Is(err, errUpstreamAuth) {
		t.Fatalf("expected errUpstreamAuth, got: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

func TestDialUpstreamWithCredsMethodNoAcceptable(t *testing.T) {
	skipIfShortNetwork(t)

	target := testTarget443()
	handshake := func(conn net.Conn, target socks5Target) error {
		if readGreetingWithUserPass(conn) == nil {
			return fmt.Errorf("unexpected upstream greeting")
		}
		_, err := conn.Write([]byte{socksVersion, socksMethodNoAcceptable})
		return err
	}
	upstreamAddr, serverErr := startScriptedUpstreamHandshake(t, target, handshake, func(net.Conn) error { return nil })

	_, err := newTestProxy(upstreamAddr).dialUpstream(target, &socks5Creds{username: "user", password: "pass"})
	if !errors.Is(err, errUpstreamProtocol) {
		t.Fatalf("expected errUpstreamProtocol, got: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

func TestDialUpstreamNoCredsUpstreamPicksUserPass(t *testing.T) {
	skipIfShortNetwork(t)

	target := testTarget443()
	handshake := func(conn net.Conn, target socks5Target) error {
		greeting := make([]byte, socksGreetingHeaderLen+1)
		if _, err := io.ReadFull(conn, greeting); err != nil {
			return err
		}
		// The shim offered only no-auth (creds==nil); selecting user/pass is a
		// protocol violation it must refuse rather than attempt a nil-creds
		// subnegotiation.
		_, err := conn.Write([]byte{socksVersion, socksMethodUserPass})
		return err
	}
	upstreamAddr, serverErr := startScriptedUpstreamHandshake(t, target, handshake, func(net.Conn) error { return nil })

	_, err := newTestProxy(upstreamAddr).dialUpstream(target, nil)
	if !errors.Is(err, errUpstreamProtocol) {
		t.Fatalf("expected errUpstreamProtocol, got: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

func TestDialUpstreamBadAuthReplyVersion(t *testing.T) {
	skipIfShortNetwork(t)

	target := testTarget443()
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
		_, err := conn.Write([]byte{0x05, socksUserPassSuccess}) // wrong subneg version
		return err
	}
	upstreamAddr, serverErr := startScriptedUpstreamHandshake(t, target, handshake, func(net.Conn) error { return nil })

	_, err := newTestProxy(upstreamAddr).dialUpstream(target, &socks5Creds{username: "user", password: "pass"})
	if !errors.Is(err, errUpstreamProtocol) {
		t.Fatalf("expected errUpstreamProtocol, got: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}
}

// readGreetingWithUserPass reads a 4-byte greeting and returns it if it is
// exactly {05,02,00,02} (no-auth plus username/password offered), else nil.
func readGreetingWithUserPass(conn net.Conn) []byte {
	greeting := make([]byte, socksGreetingHeaderLen+2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return nil
	}
	if !bytes.Equal(greeting, []byte{socksVersion, 0x02, socksMethodNoAuth, socksMethodUserPass}) {
		return nil
	}
	return greeting
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

func TestHandlePassesCredentialsThroughToUpstream(t *testing.T) {
	skipIfShortNetwork(t)

	tests := []struct {
		name string
		user string
		pass string
	}{
		{name: "basic", user: "user", pass: "pass"},
		{name: "empty credentials forwarded as-is", user: "", pass: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			target := testTarget443()
			upstreamAddr, serverErr := startScriptedUpstreamHandshake(t, target,
				performUpstreamUserPassHandshake(tt.user, tt.pass),
				func(conn net.Conn) error {
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
			performClientUserPassHandshake(t, client, tt.user, tt.pass)

			if _, err := client.Write(buildConnectRequest(target)); err != nil {
				t.Fatalf("Write CONNECT request: %v", err)
			}
			reply := readN(t, client, 10)
			if reply[0] != socksVersion || reply[1] != socksRepSucceeded {
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
		})
	}
}

func TestHandleReturnsGeneralFailureWhenUpstreamRejectsAuth(t *testing.T) {
	skipIfShortNetwork(t)

	// A reachable target proves whether a (forbidden) direct fallback happened.
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
		_, err := conn.Write([]byte{socksUserPassVersion, 0x01}) // reject
		return err
	}
	upstreamAddr, serverErr := startScriptedUpstreamHandshake(t, target, handshake, func(net.Conn) error { return nil })

	client, _ := startHandleSession(t, newTestProxy(upstreamAddr))
	performClientUserPassHandshake(t, client, "user", "wrong")

	if _, err := client.Write(buildConnectRequest(target)); err != nil {
		t.Fatalf("Write CONNECT request: %v", err)
	}
	reply := readN(t, client, 10)
	if reply[1] != socksRepGeneralFailure {
		t.Fatalf("unexpected rep code: 0x%02x", reply[1])
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("mock upstream failed: %v", err)
	}

	select {
	case <-accepted:
		t.Fatal("direct fallback occurred despite upstream auth rejection")
	case <-time.After(150 * time.Millisecond):
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

func performClientUserPassHandshake(t *testing.T, client net.Conn, user, pass string) {
	t.Helper()
	writeGreeting(t, client, socksMethodNoAuth, socksMethodUserPass)
	authResp := readN(t, client, 2)
	if !bytes.Equal(authResp, []byte{socksVersion, socksMethodUserPass}) {
		t.Fatalf("unexpected auth response: %x", authResp)
	}
	if _, err := client.Write(buildUserPassRequest(&socks5Creds{username: user, password: pass})); err != nil {
		t.Fatalf("Write auth request: %v", err)
	}
	subResp := readN(t, client, 2)
	if !bytes.Equal(subResp, []byte{socksUserPassVersion, socksUserPassSuccess}) {
		t.Fatalf("unexpected auth status: %x", subResp)
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
