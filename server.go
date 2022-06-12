package robin

import (
	"bufio"
	"crypto/sha1"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtaci/kcp-go"
	"go.uber.org/zap"
	"golang.org/x/crypto/pbkdf2"
)

var (
  ErrServerClosed = errors.New("[robin]: server closed")
)

type any = interface{}

type Handler interface {
  ServeKCP(ResponseWriter, *Request)
}

type ResponseWriter interface {
  Write([]byte)(n int, err error)
}

type Request struct {
  Name string
  Data any 
}

type Server struct {
  Listener *kcp.Listener
  Handler Handler
  Logger *zap.SugaredLogger


  // ReadTimeout is the maximum duration for reading the entire
	// request, including the body.
	ReadTimeout time.Duration
	// WriteTimeout is the maximum duration before timing out
	// writes of the response.
	WriteTimeout time.Duration
	// IdleTimeout is the maximum amount of time to wait for the
	// next request.
	IdleTimeout time.Duration

  // 'block' is the block encryption algorithm to encrypt packets.
  Block kcp.BlockCrypt
  // 'dataShards', 'parityShards' specifiy how many parity packets will be generated following the data packets.
  DataShards int
  ParityShards int

  mu         sync.Mutex
	activeConn map[*conn]struct{}
	doneChan   chan struct{}
	onShutdown []func()
  inShutdown int32
}

func (srv *Server) Serve(ln *kcp.Listener) error {
  // close kcp listener in the end
  l := &onceCloseListener{Listener: ln}
	defer func() {
		if err := l.Close(); err != nil {
			panic(err)
		}
	}()

  srv.Listener = ln

  var tempDelay time.Duration // how long to sleep on accept failure

  for {
    rw, err := ln.AcceptKCP()
    srv.Logger.Infof("[robin]: new connection accpeted, %s", rw.RemoteAddr().String())
    // handle acception errors
    if err != nil {
      select {
       case <-srv.getDoneChan():
          return ErrServerClosed
        default:
			}

      if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
        srv.Logger.Errorf("[robin]: Accept error: %v; retrying in %v", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
    }
    tempDelay = 0

    c := srv.newConn(rw)
		c.setState(c.rwc, StateNew)

    go c.serve()
  }
}

// onceCloseListener wraps a net.Listener, protecting it from
// multiple Close calls.
type onceCloseListener struct {
	net.Listener
	once     sync.Once
	closeErr error
}

func (oc *onceCloseListener) Close() error {
	oc.once.Do(oc.close)
	return oc.closeErr
}

func (oc *onceCloseListener) close() { oc.closeErr = oc.Listener.Close() }

func (srv *Server) getDoneChan() <-chan struct{} {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	return srv.getDoneChanLocked()
}

func (srv *Server) getDoneChanLocked() chan struct{} {
	if srv.doneChan == nil {
		srv.doneChan = make(chan struct{})
	}
	return srv.doneChan
}

func (srv *Server) closeDoneChanLocked() {
	ch := srv.getDoneChanLocked()
	select {
	case <-ch:
		// Already closed. Don't close again.
	default:
		// Safe to close here. We're the only closer, guarded
		// by s.mu.
		close(ch)
	}
}

func (srv *Server) trackConn(c *conn, add bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.activeConn == nil {
		srv.activeConn = make(map[*conn]struct{})
	}
	if add {
		srv.activeConn[c] = struct{}{}
	} else {
		delete(srv.activeConn, c)
	}
}

// Close immediately closes all active net.Listeners and any
// connections in state StateNew, StateActive, or StateIdle. For a
// graceful shutdown, use Shutdown.
//
// Close does not attempt to close (and does not even know about)
// any hijacked connections, such as WebSockets.
//
// Close returns any error returned from closing the Server's
// underlying Listener(s).
func (srv *Server) Close() error {
	atomic.StoreInt32(&srv.inShutdown, 1)
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.closeDoneChanLocked()
	err := srv.closeListenerLocked()
	for c := range srv.activeConn {
		_ = c.rwc.Close()
		delete(srv.activeConn, c)
	}
	return err
}

func (srv *Server) closeListenerLocked() error {
	var err error
	ln := srv.Listener
  if cerr := (*ln).Close(); cerr != nil && err == nil {
    err = cerr
  }
	
	return err
}

// Create new connection from rwc.
func (srv *Server) newConn(rwc net.Conn) *conn {
	c := &conn{
		server: srv,
		rwc:    rwc,
	}
	return c
}


func (srv *Server) shuttingDown() bool {
	// TODO: replace inShutdown with the existing atomicBool type;
	// see https://github.com/golang/go/issues/20239#issuecomment-381434582
	return atomic.LoadInt32(&srv.inShutdown) != 0
}

// shutdownPollInterval is how often we poll for quiescence
// during Server.Shutdown. This is lower during tests, to
// speed up tests.
// Ideally we could find a solution that doesn't involve polling,
// but which also doesn't have a high runtime cost (and doesn't
// involve any contentious mutexes), but that is left as an
// exercise for the reader.
var shutdownPollInterval = 500 * time.Millisecond

// Shutdown gracefully shuts down the server without interrupting any
// active connections. Shutdown works by first closing all open
// listeners, then closing all idle connections, and then waiting
// indefinitely for connections to return to idle and then shut down.
// If the provided context expires before the shutdown is complete,
// Shutdown returns the context's error, otherwise it returns any
// error returned from closing the Server's underlying Listener(s).
//
// When Shutdown is called, Serve, ListenAndServe, and
// ListenAndServeTLS immediately return ErrServerClosed. Make sure the
// program doesn't exit and waits instead for Shutdown to return.
//
// Shutdown does not attempt to close nor wait for hijacked
// connections such as WebSockets. The caller of Shutdown should
// separately notify such long-lived connections of shutdown and wait
// for them to close, if desired. See RegisterOnShutdown for a way to
// register shutdown notification functions.
//
// Once Shutdown has been called on a server, it may not be reused;
// future calls to methods such as Serve will return ErrServerClosed.
func (srv *Server) Shutdown() error {
  srv.Logger.Info("[robin]: start to shutdown...")

	atomic.StoreInt32(&srv.inShutdown, 1)

	srv.mu.Lock()
	lnerr := srv.closeListenerLocked()
	srv.closeDoneChanLocked()
	for _, f := range srv.onShutdown {
		go f()
	}
	srv.mu.Unlock()

	ticker := time.NewTicker(shutdownPollInterval)
	defer ticker.Stop()
	for {
		if srv.closeIdleConns() {
      srv.Logger.Info("[robin]: shutdown completed")
			return lnerr
		}
		select {
		case <-ticker.C:
			srv.mu.Lock()
			num := len(srv.activeConn)
			srv.mu.Unlock()
      srv.Logger.Infof("[robin]: waiting on %v connections", num)
		}
	}
}

// closeIdleConns closes all idle connections and reports whether the
// server is quiescent.
func (srv *Server) closeIdleConns() bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	quiescent := true
	for c := range srv.activeConn {
		st, unixSec := c.getState()
		// treat StateNew connections as if
		// they're idle if we haven't read the first request's
		// header in over 5 seconds.
		if st == StateNew && unixSec < time.Now().Unix()-5 {
			st = StateIdle
		}
		if st != StateIdle || unixSec == 0 {
			// Assume unixSec == 0 means it's a very new
			// connection, without state set yet.
			quiescent = false
			continue
		}

		_ = c.rwc.Close()
		delete(srv.activeConn, c)
	}
	return quiescent
}

func (srv *Server) idleTimeout() time.Duration {
	if srv.IdleTimeout != 0 {
		return srv.IdleTimeout
	}
	return srv.ReadTimeout
}


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

	// conn loop start
	for {
		// handle connection timeout
		if d := c.server.ReadTimeout; d != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(d))
		}

    buf := make([]byte, 4096)
    n, err := c.bufr.Read(buf)

    c.server.Logger.Infof("data received: %s", buf[:n])
    c.server.Logger.Infof("current client count: %d", len(c.server.activeConn))

		if err != nil && err != io.EOF {
			// TODO: log error instead?
			panic(err)
		}

		// set underline conn to active mode
		c.setState(c.rwc, StateActive)

		// set rwc to idle state again
		c.setState(c.rwc, StateIdle)
		// handle connection idle
		if d := c.server.idleTimeout(); d != 0 {
			c.rwc.SetReadDeadline(time.Now().Add(d))
			if _, err := c.bufr.Peek(4); err != nil {
				return
			}
		}
		c.rwc.SetReadDeadline(time.Time{})
	}
}

func Key(pass, salt string) (key []byte) {
  key = pbkdf2.Key([]byte(pass), []byte(salt), 1024, 32, sha1.New) 
  return
}

func ListenAndServe(addr string, key []byte, handler Handler) error {
  // using AES128 as default encrypt block
  block, err := kcp.NewAESBlockCrypt(key)
  if err != nil {
    return err
  }

  var srv = &Server{
    Block: block,
    // Check https://github.com/klauspost/reedsolomon for details
    DataShards: 10,
    ParityShards: 3,
    Handler: handler,
  }

  ln, err := kcp.ListenWithOptions(addr, block, srv.DataShards, srv.ParityShards)
  if err != nil {
    return err
  }

  // using sugared zap as logger
  logger, _ := zap.NewProduction()
  slogger := logger.Sugar()
  srv.Logger = slogger

  return srv.Serve(ln)
}

// POOL  -------------------------------------------------

var (
	bufioReaderPool sync.Pool
	bufioWriterPool sync.Pool

	// frame body bytearray pooling
	// bytePool *BytePool = NewBytePool(516, maxFrameSize)
)

func newBufioReader(r io.Reader) *bufio.Reader {
	if v := bufioReaderPool.Get(); v != nil {
		br := v.(*bufio.Reader)
		br.Reset(r)
		return br
	}
	// Note: if this reader size is ever changed, update
	// TestHandlerBodyClose's assumptions.
	return bufio.NewReader(r)
}

func putBufioReader(br *bufio.Reader) {
	br.Reset(nil)
	bufioReaderPool.Put(br)
}

func newBufioWriter(w io.Writer) *bufio.Writer {
	if v := bufioWriterPool.Get(); v != nil {
		bw := v.(*bufio.Writer)
		bw.Reset(w)
		return bw
	}
	// Note: if this reader size is ever changed, update
	// TestHandlerBodyClose's assumptions.
	return bufio.NewWriter(w)
}

func putBufioWriter(bw *bufio.Writer) {
	bw.Reset(nil)
	bufioWriterPool.Put(bw)
}
