package main

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

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
