package main

import (
	"context"
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
var errUpstreamAuth = errors.New("upstream rejected credentials")

// proxy holds the routing configuration and upstream backoff state shared by
// the SOCKS5 and HTTP handlers.
type proxy struct {
	upstream          string
	dialTimeout       time.Duration // TCP connect + SOCKS5 greeting to upstream
	connectTimeout    time.Duration // SOCKS5 CONNECT reply from upstream
	clientReadTimeout time.Duration // client greeting/request reads
	backoff           *upstreamBackoffState
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

// dial tries the upstream SOCKS5 proxy first, falling back to a direct
// connection only when the upstream is unreachable; any other failure is
// returned to the caller.
// Canceling ctx unblocks the caller promptly. An in-flight upstream handshake
// is not torn down on cancel: a cancel proves nothing about the upstream, so
// the handshake rides out its own deadlines detached (like http.Transport's
// abandoned dials) and its verdict still settles the backoff cache.
func (p *proxy) dial(ctx context.Context, target socks5Target, creds *socks5Creds) (net.Conn, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	if p.backoff.shouldSkip(p.upstream, time.Now()) {
		return dialDirect(ctx, target)
	}

	type upstreamResult struct {
		conn net.Conn
		err  error
	}
	ch := make(chan upstreamResult, 1)
	go func() {
		conn, err := p.dialUpstream(target, creds)
		ch <- upstreamResult{conn, err}
	}()

	var conn net.Conn
	var err error
	select {
	case r := <-ch:
		conn, err = r.conn, r.err
	case <-ctx.Done():
		// Nobody is waiting for a fallback either; just settle the backoff
		// cache once the abandoned handshake resolves.
		go func() {
			r := <-ch
			switch {
			case r.err == nil:
				p.backoff.clear(p.upstream)
				r.conn.Close()
			case errors.As(r.err, new(upstreamConnectError)):
				p.backoff.clear(p.upstream) // upstream alive; same as attended path below
			case errors.Is(r.err, errUpstreamUnavailable):
				p.backoff.markUnavailable(p.upstream, time.Now())
				log.Printf("upstream unavailable: %v (abandoned by canceled request)", r.err)
			}
		}()
		return nil, false, ctx.Err()
	}

	if err == nil {
		p.backoff.clear(p.upstream)
		return conn, true, nil
	}
	var connectErr upstreamConnectError
	if errors.As(err, &connectErr) {
		// Any CONNECT reply proves the greeting succeeded, i.e. the upstream is
		// alive: clear backoff and relay its verdict instead of bypassing it.
		p.backoff.clear(p.upstream)
		return nil, false, err
	}
	// errUpstreamAuth and errUpstreamProtocol land here: deliberate
	// rejections must not be bypassed via a direct fallback.
	if !errors.Is(err, errUpstreamUnavailable) {
		return nil, false, err
	}

	// Covers CONNECT reply timeouts too: back off so a wedged upstream
	// doesn't stall every connection for connectTimeout.
	p.backoff.markUnavailable(p.upstream, time.Now())
	log.Printf("upstream unavailable: %v; falling back to direct", err)
	return dialDirect(ctx, target)
}

func dialDirect(ctx context.Context, target socks5Target) (net.Conn, bool, error) {
	conn, err := (&net.Dialer{Timeout: directDialTimeout}).DialContext(ctx, "tcp", target.addr)
	if err != nil {
		return nil, false, err
	}
	return conn, false, nil
}
