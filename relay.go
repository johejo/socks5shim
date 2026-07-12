package main

import (
	"bufio"
	"io"
	"net"
)

// relayBuffered flushes any bytes already buffered by br to remote, then
// relays the two connections.
func relayBuffered(client, remote net.Conn, br *bufio.Reader) {
	if n := br.Buffered(); n > 0 {
		buffered, _ := br.Peek(n)
		if _, err := remote.Write(buffered); err != nil {
			return
		}
		br.Discard(n)
	}
	relay(client, remote)
}

func relay(a, b net.Conn) {
	done := make(chan struct{})
	go func() {
		io.Copy(b, a)
		closeWrite(b)
		close(done)
	}()
	io.Copy(a, b)
	closeWrite(a)
	<-done
}

func closeWrite(c net.Conn) {
	if tc, ok := c.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
}
