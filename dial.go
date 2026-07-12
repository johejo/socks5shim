package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
)

const (
	defaultUpstreamDialTimeout    = 2 * time.Second
	defaultUpstreamConnectTimeout = 7 * time.Second
	defaultClientReadTimeout      = 5 * time.Second
	directDialTimeout             = 10 * time.Second
	upstreamUnavailableBackoff    = 3 * time.Second
)

var errUpstreamUnavailable = errors.New("upstream unavailable")
var errUpstreamProtocol = errors.New("upstream protocol error")

// proxy holds the routing configuration and upstream backoff state shared by
// the SOCKS5 and HTTP handlers.
type proxy struct {
	upstream               string
	dialTimeout            time.Duration // TCP connect + SOCKS5 greeting to upstream
	connectTimeout         time.Duration // SOCKS5 CONNECT reply from upstream
	clientReadTimeout      time.Duration // client greeting/request reads
	fallbackGeneralFailure bool
	backoff                *upstreamBackoffState
}

func (p *proxy) readTimeout() time.Duration {
	if p.clientReadTimeout <= 0 {
		return defaultClientReadTimeout
	}
	return p.clientReadTimeout
}

type upstreamConnectError struct {
	rep byte
}

func (e upstreamConnectError) Error() string {
	return fmt.Sprintf("upstream CONNECT failed: rep=0x%02x", e.rep)
}

// fallbackEligible reports whether the reply code is a connection failure
// that may not recur on a direct path, safe to retry. Deliberate rejections
// (0x02) and capability mismatches (0x07/0x08) are not. General failure
// (0x01) is ambiguous, so it falls back only when opted in.
func (e upstreamConnectError) fallbackEligible(fallbackGeneralFailure bool) bool {
	switch e.rep {
	case socksRepGeneralFailure:
		return fallbackGeneralFailure
	case socksRepNetworkUnreachable, socksRepHostUnreachable,
		socksRepConnectionRefused, socksRepTTLExpired:
		return true
	}
	return false
}

type upstreamBackoffState struct {
	mu       sync.Mutex
	until    map[string]time.Time
	duration time.Duration
}

func newUpstreamBackoffState(duration time.Duration) *upstreamBackoffState {
	return &upstreamBackoffState{
		until:    map[string]time.Time{},
		duration: duration,
	}
}

func (s *upstreamBackoffState) shouldSkip(addr string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	until, ok := s.until[addr]
	if !ok {
		return false
	}
	if now.After(until) {
		delete(s.until, addr)
		return false
	}
	return true
}

func (s *upstreamBackoffState) markUnavailable(addr string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.until[addr] = now.Add(s.duration)
}

func (s *upstreamBackoffState) clear(addr string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.until, addr)
}

func replyCodeFromDialError(err error) byte {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return socksRepHostUnreachable
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return socksRepHostUnreachable
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case syscall.ECONNREFUSED:
			return socksRepConnectionRefused
		case syscall.ENETUNREACH:
			return socksRepNetworkUnreachable
		case syscall.EHOSTUNREACH, syscall.ETIMEDOUT:
			return socksRepHostUnreachable
		}
	}
	return socksRepGeneralFailure
}

// dial tries the upstream SOCKS5 proxy first; on failure, connects directly.
func (p *proxy) dial(target socks5Target) (net.Conn, bool, error) {
	if p.backoff.shouldSkip(p.upstream, time.Now()) {
		return dialDirect(target)
	}

	conn, err := p.dialUpstream(target)
	if err == nil {
		p.backoff.clear(p.upstream)
		return conn, true, nil
	}
	var connectErr upstreamConnectError
	if errors.As(err, &connectErr) {
		if !connectErr.fallbackEligible(p.fallbackGeneralFailure) {
			return nil, false, err
		}
		// The greeting succeeded, so the upstream is alive: fall back
		// without poisoning the backoff cache.
		p.backoff.clear(p.upstream)
		log.Printf("upstream CONNECT failed (rep=0x%02x) for %s; falling back to direct", connectErr.rep, target.addr)
		return dialDirect(target)
	}
	if !errors.Is(err, errUpstreamUnavailable) {
		return nil, false, err
	}

	// Covers CONNECT reply timeouts too: back off so a wedged upstream
	// doesn't stall every connection for connectTimeout.
	p.backoff.markUnavailable(p.upstream, time.Now())
	log.Printf("upstream unavailable: %v; falling back to direct", err)
	return dialDirect(target)
}

func dialDirect(target socks5Target) (net.Conn, bool, error) {
	conn, err := net.DialTimeout("tcp", target.addr, directDialTimeout)
	if err != nil {
		return nil, false, err
	}
	return conn, false, nil
}
