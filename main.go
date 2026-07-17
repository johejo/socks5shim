package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"time"
)

var version string

func main() {
	listen := flag.String("listen", "127.0.0.1:1081", "listen address")
	httpListen := flag.String("http-listen", "", "HTTP proxy listen address (empty to disable)")
	upstream := flag.String("upstream", "127.0.0.1:1080", "upstream SOCKS5 proxy address")
	dialTimeout := flag.Duration("dial-timeout", defaultUpstreamDialTimeout, "timeout for TCP connect and SOCKS5 greeting to upstream")
	connectTimeout := flag.Duration("connect-timeout", defaultUpstreamConnectTimeout, "timeout for SOCKS5 CONNECT reply from upstream")
	clientReadTimeout := flag.Duration("client-handshake-timeout", defaultClientReadTimeout, "timeout for reading SOCKS5 greeting/request from client")
	fallbackGeneralFailure := flag.Bool("fallback-on-general-failure", false, "fall back to a direct connection when the upstream answers CONNECT with general failure (0x01); bypasses upstreams that use 0x01 for policy denials")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(resolveVersion())
		return
	}

	p := &proxy{
		upstream:               *upstream,
		dialTimeout:            *dialTimeout,
		connectTimeout:         *connectTimeout,
		clientReadTimeout:      *clientReadTimeout,
		fallbackGeneralFailure: *fallbackGeneralFailure,
		backoff:                newUpstreamBackoffState(upstreamUnavailableBackoff),
	}

	if *httpListen != "" {
		httpLn, err := net.Listen("tcp", *httpListen)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("HTTP proxy listening on %s, upstream %s (dial-timeout %s, connect-timeout %s)", *httpListen, *upstream, *dialTimeout, *connectTimeout)
		srv := p.newHTTPServer()
		go func() {
			log.Printf("http server exited: %v", srv.Serve(httpLn))
		}()
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("SOCKS5 listening on %s, upstream %s (dial-timeout %s, connect-timeout %s)", *listen, *upstream, *dialTimeout, *connectTimeout)

	acceptLoop(ln, "socks5", p.handle)
}

// acceptLoop retries Accept errors with backoff so a persistent failure such
// as EMFILE does not busy-spin.
func acceptLoop(ln net.Listener, name string, handler func(net.Conn)) {
	var delay time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			if delay == 0 {
				delay = 5 * time.Millisecond
			} else {
				delay *= 2
			}
			if maxDelay := 1 * time.Second; delay > maxDelay {
				delay = maxDelay
			}
			log.Printf("%s accept: %v; retrying in %s", name, err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		go handler(conn)
	}
}

func resolveVersion() string {
	if version != "" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if ok && info != nil && info.Main.Version != "" {
		return info.Main.Version
	}
	return ""
}
