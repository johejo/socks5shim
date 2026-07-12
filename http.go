package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strconv"
	"time"
)

// newHTTPServer builds the HTTP proxy front-end: plain requests go through
// a ReverseProxy whose Transport dials via the SOCKS5-or-direct path, and
// CONNECT is tunneled by hijacking the connection.
func (p *proxy) newHTTPServer() *http.Server {
	rp := &httputil.ReverseProxy{
		// The outbound request already carries the client's absolute-form
		// URL (cloned by ReverseProxy); nothing to rewrite. Rewrite mode
		// also strips inbound Forwarded/X-Forwarded-* without adding any.
		Rewrite: func(*httputil.ProxyRequest) {},
		Transport: &http.Transport{
			DialContext: p.dialContext,
			// A proxy must not inject Accept-Encoding and transparently
			// decompress on the client's behalf.
			DisableCompression: true,
			// Idle pooled conns pin upstream SOCKS5 sessions; bound
			// their lifetime.
			IdleConnTimeout: 90 * time.Second,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("HTTP PLAIN FAIL %s: %v", r.Host, err)
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	return &http.Server{
		Handler:           p.httpHandler(rp),
		ReadHeaderTimeout: p.readTimeout(),
		IdleTimeout:       2 * time.Minute,
		// ReadTimeout and WriteTimeout stay zero: hijacked CONNECT
		// tunnels and streamed bodies must not carry deadlines.
	}
}

func (p *proxy) httpHandler(rp *httputil.ReverseProxy) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "CONNECT" {
			p.serveConnect(w, r)
			return
		}
		// Only absolute-form http targets are accepted, as a proxy
		// should. Anything else — origin-form, https, an h2c preface —
		// would make the Transport originate the connection itself
		// (even TLS) rather than forward the client's request.
		if r.URL.Scheme != "http" || r.URL.Host == "" {
			http.Error(w, "proxy requires an absolute-form http URL", http.StatusBadRequest)
			return
		}
		rp.ServeHTTP(w, r)
	})
}

func (p *proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	host, port, err := parseHostPort(r.Host, "443")
	if err != nil {
		http.Error(w, "bad CONNECT target", http.StatusBadRequest)
		return
	}

	target := buildHTTPTarget(host, port)
	remote, viaUpstream, err := p.dial(r.Context(), target, nil)
	if err != nil {
		log.Printf("HTTP CONNECT FAIL %s: %v", target.addr, err)
		http.Error(w, "dial failed", http.StatusBadGateway)
		return
	}
	defer remote.Close()

	if viaUpstream {
		log.Printf("HTTP CONNECT PROXY %s", target.addr)
	} else {
		log.Printf("HTTP CONNECT DIRECT %s -> %s", target.addr, remote.RemoteAddr())
	}

	conn, brw, err := http.NewResponseController(w).Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// Hijack cleared all deadlines and the Server sets no
	// ReadTimeout/WriteTimeout, so the tunnel runs unbounded like the
	// SOCKS path. brw.Reader may hold bytes an eager client sent behind
	// the CONNECT header (e.g. a TLS ClientHello); relayBuffered flushes
	// them before the raw relay.
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}

	relayBuffered(conn, remote, brw.Reader)
}

// dialContext adapts the SOCKS5-or-direct dial path to http.Transport. The
// request ctx is honored; see dial for its cancellation behavior.
func (p *proxy) dialContext(ctx context.Context, _, addr string) (net.Conn, error) {
	host, port, err := parseHostPort(addr, "80")
	if err != nil {
		return nil, err
	}
	target := buildHTTPTarget(host, port)
	remote, viaUpstream, err := p.dial(ctx, target, nil)
	if err != nil {
		return nil, err
	}
	if viaUpstream {
		log.Printf("HTTP PLAIN PROXY %s", target.addr)
	} else {
		log.Printf("HTTP PLAIN DIRECT %s -> %s", target.addr, remote.RemoteAddr())
	}
	return remote, nil
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
