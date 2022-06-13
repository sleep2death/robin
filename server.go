package robin

import (
	"bufio"
	"crypto/sha1"
	"errors"
	"io"
	"net"
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

type Handler interface {
	Serve(ResponseWriter, *Request)
}

type Request struct {
	conn    *conn
	TypeUrl string
	Data    []byte
}

func (req *Request) RemoteAddr() string {
	if req.conn != nil {
		return req.conn.remoteAddr
	}
	return "0.0.0.0"
}

type Server struct {
	Listener *kcp.Listener
	Handler  Handler
	Logger   *zap.SugaredLogger

	// max buf size
	MaxBufSize uint

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
	DataShards   int
	ParityShards int

	mu         sync.Mutex
	activeConn map[*conn]struct{}
	doneChan   chan struct{}
	onShutdown []func()
	inShutdown int32
}

func (srv *Server) Serve() error {
	// close kcp listener in the end
	l := &onceCloseListener{Listener: srv.Listener}
	defer func() {
		if err := l.Close(); err != nil {
			panic(err)
		}
	}()

	var tempDelay time.Duration // how long to sleep on accept failure

	for {
		rw, err := srv.Listener.AcceptKCP()
		srv.Logger.Infof("[robin]: new connection accepted, %s", rw.RemoteAddr().String())
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
var shutdownPollInterval = 500 * time.Millisecond

// Shutdown gracefully shuts down the server without interrupting any
// active connections.
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

func DefaultServer(addr string, key []byte, handler Handler) (*Server, error) {
	// using AES128 as default encrypt block
	block, err := kcp.NewAESBlockCrypt(key)
	if err != nil {
		return nil, err
	}

	var srv = &Server{
		Block:      block,
		MaxBufSize: 4096,
		// Check https://github.com/klauspost/reedsolomon for details
		DataShards:   10,
		ParityShards: 3,
		Handler:      handler,

		IdleTimeout:  time.Second * 5,
		WriteTimeout: time.Second * 5,
		ReadTimeout:  time.Second * 5,
	}

	ln, err := kcp.ListenWithOptions(addr, block, srv.DataShards, srv.ParityShards)
	if err != nil {
		return nil, err
	}

	// using sugared zap as logger
	logger, _ := zap.NewProduction()
	slogger := logger.Sugar()

	srv.Logger = slogger
	srv.Listener = ln

	return srv, nil
}

func Key(pass, salt string) (key []byte) {
	key = pbkdf2.Key([]byte(pass), []byte(salt), 1024, 32, sha1.New)
	return
}

func ListenAndServe(addr string, key []byte, handler Handler) error {
	srv, err := DefaultServer(addr, key, handler)
	if err != nil {
		return err
	}
	return srv.Serve()
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
