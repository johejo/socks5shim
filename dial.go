package main

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"
)

const (
	defaultUpstreamDialTimeout    = 2 * time.Second
	defaultUpstreamConnectTimeout = 7 * time.Second
	defaultClientReadTimeout      = 5 * time.Second
	directDialTimeout             = 10 * time.Second
	upstreamUnavailableBackoff    = 3 * time.Second
)

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
		p.settleBackoff(err)
		ch <- upstreamResult{conn, err}
	}()

	var conn net.Conn
	var err error
	select {
	case r := <-ch:
		conn, err = r.conn, r.err
	case <-ctx.Done():
		// The dial goroutine settles the backoff cache once the abandoned
		// handshake resolves; nobody is waiting for a fallback either, so
		// just reap the orphaned conn.
		go func() {
			r := <-ch
			if r.conn != nil {
				r.conn.Close()
			} else if errors.Is(r.err, errUpstreamUnavailable) {
				log.Printf("upstream unavailable: %v (abandoned by canceled request)", r.err)
			}
		}()
		return nil, false, ctx.Err()
	}

	if err == nil {
		return conn, true, nil
	}
	if errors.As(err, new(upstreamConnectError)) {
		// Any CONNECT reply proves the upstream is alive: relay its verdict
		// instead of bypassing it.
		return nil, false, err
	}
	// errUpstreamAuth and errUpstreamProtocol land here: deliberate
	// rejections must not be bypassed via a direct fallback.
	if !errors.Is(err, errUpstreamUnavailable) {
		return nil, false, err
	}

	log.Printf("upstream unavailable: %v; falling back to direct", err)
	return dialDirect(ctx, target)
}

// settleBackoff records dialUpstream's verdict in the backoff cache: any
// completed handshake (success or a CONNECT reply) proves the upstream alive
// and clears it; unreachability marks it for the backoff window (covering
// CONNECT reply timeouts too, so a wedged upstream doesn't stall every
// connection for connectTimeout); deliberate rejections (auth, protocol)
// leave it untouched.
func (p *proxy) settleBackoff(err error) {
	switch {
	case err == nil, errors.As(err, new(upstreamConnectError)):
		p.backoff.clear(p.upstream)
	case errors.Is(err, errUpstreamUnavailable):
		p.backoff.markUnavailable(p.upstream, time.Now())
	}
}

var directDialer = net.Dialer{Timeout: directDialTimeout}

func dialDirect(ctx context.Context, target socks5Target) (net.Conn, bool, error) {
	conn, err := directDialer.DialContext(ctx, "tcp", target.addr)
	if err != nil {
		return nil, false, err
	}
	return conn, false, nil
}
