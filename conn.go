package robin

import (
	"bufio"
	"io"
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/protobuf/proto"
)

// A ConnState represents the state of a client connection to a server.
type ConnState int

const (
	// StateNew represents a new connection that is expected to
	StateNew ConnState = iota

	// StateActive represents a connection that has read 1 or more
	StateActive

	// StateIdle represents a connection that has finished
	StateIdle

	// StateClosed represents a closed connection.
	StateClosed
)

type conn struct {
	// server is the server on which the connection arrived.
	// Immutable; never nil.
	server *Server

	// rwc is the underlying network connection.
	// This is never wrapped by other types and is the value given out
	// to CloseNotifier callers. It is usually of type *net.TCPConn
	rwc net.Conn

	// remoteAddr is rwc.RemoteAddr().String(). It is not populated synchronously
	// inside the Listener's Accept goroutine, as some implementations block.
	// It is populated immediately inside the (*conn).serve goroutine.
	// This is the value of a Handler's (*Request).RemoteAddr.
	remoteAddr string

	// werr is set to the first write error to rwc.
	// It is set via checkConnErrorWriter{w}, where bufw writes.
	werr error

	// bufr reads from r.
	bufr *bufio.Reader

	// bufw writes to checkConnErrorWriter{c}, which populates werr on error.
	bufw *bufio.Writer

	curState struct{ atomic uint64 } // packed (unixtime<<8|uint8(ConnState))
}

var stateName = map[ConnState]string{
	StateNew:    "new",
	StateActive: "active",
	StateIdle:   "idle",
	StateClosed: "closed",
}

func (c ConnState) String() string {
	return stateName[c]
}

func (c *conn) setState(nc net.Conn, state ConnState) {
	srv := c.server
	switch state {
	case StateNew:
		srv.trackConn(c, true)
	case StateClosed:
		srv.trackConn(c, false)
	}
	if state > 0xff || state < 0 {
		panic("internal error")
	}
	packedState := uint64(time.Now().Unix()<<8) | uint64(state)
	atomic.StoreUint64(&c.curState.atomic, packedState)
}

func (c *conn) getState() (state ConnState, unixSec int64) {
	packedState := atomic.LoadUint64(&c.curState.atomic)
	return ConnState(packedState & 0xff), int64(packedState >> 8)
}

func (c *conn) finalFlush() {
	if c.bufr != nil {
		// Steal the bufio.Reader (~4KB worth of memory) and its associated
		// reader for a future connection.
		putBufioReader(c.bufr)
		c.bufr = nil
	}

	if c.bufw != nil {
		// flush it, anyway
		_ = c.bufw.Flush()
		// Steal the bufio.Writer (~4KB worth of memory) and its associated
		// writer for a future connection.
		putBufioWriter(c.bufw)
		c.bufw = nil
	}
}

// Close the connection.
func (c *conn) close() {
	c.finalFlush()
	// close it anyway
	_ = c.rwc.Close()
}

// Serve a new connection.
func (c *conn) serve() {
	// set remote addr
	c.remoteAddr = c.rwc.RemoteAddr().String()

	defer func() {
		// recover from reading panic, if failed log the err
		if err := recover(); err != nil && c.server.shuttingDown() == false {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			c.server.Logger.Errorf("[robin]: panic serving %v: %v\n%s", c.remoteAddr, err, buf)
		}
		// close the connection
		// it will flush the writer, and put the reader&writer back to pool
		c.close()
		// untrack the connection
		c.setState(c.rwc, StateClosed)
	}()

	// wrap the underline conn with bufio reader&writer
	// sync pool inside
	c.bufr = newBufioReader(c.rwc)
	c.bufw = newBufioWriter(c.rwc)

	// read buf
	buf := make([]byte, c.server.MaxBufSize)

	// conn loop start
	for {
		// handle connection timeout
		if d := c.server.ReadTimeout; d != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(d))
		}

		n, err := c.bufr.Read(buf[:cap(buf)])
		if err != nil && err != io.EOF {
			panic(err)
		}

		// don't need data frame handling,
		// cause kcp already did it for us
		buf := buf[:n]

		req := new(Request)
		req.conn = c
		if err := Unmarshal(buf, req); err != nil {
			panic(err)
		}
		// c.server.Logger.Infof("receiving: %s, %s", req.TypeUrl, req.Data)
		// set underline conn to active mode
		c.setState(c.rwc, StateActive)
		w := NewResponseWriter(c.bufw)

		// pass to handler
		if c.server.Handler != nil {
			c.server.Handler.Serve(w, req)
		}

		// flush, if any data to write
		if w.Buffered() > 0 {
			if d := c.server.WriteTimeout; d != 0 {
				c.rwc.SetWriteDeadline(time.Now().Add(d))
			}

			if err := w.Flush(); err != nil {
				panic(err)
			}
		}

		// if the writer require close, then return and close the conn
		if !w.KeepAlive() {
			return
		}

		// set rwc to idle state again
		c.setState(c.rwc, StateIdle)
		// handle connection idle
		if d := c.server.idleTimeout(); d != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(d))
			if _, err := c.bufr.Peek(4); err != nil {
				c.server.Logger.Warnf("read timeout: %v, %s", err, c.remoteAddr)
				return
			}
		}
		c.rwc.SetReadDeadline(time.Time{})
	}
}

func Unmarshal(data []byte, req *Request) error {
	var msg any.Any
	err := proto.Unmarshal(data, &msg)

	if err != nil {
		return err
	}

	req.Data = msg.GetValue()
	req.TypeUrl = msg.GetTypeUrl()
	return nil
}
