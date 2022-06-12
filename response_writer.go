package robin

import (
	"errors"
	"io"
	"net/http"

	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/protobuf/proto"
)

const (
	noWritten        = 0
	defaultKeepAlive = true
	defaultStatus    = http.StatusOK
)

var (
	ErrNotFlusher = errors.New("this writer is not a flusher")
)

type BufFlusher interface {
	// Flush writes any buffered data to the underlying io.Writer.
	Flush() error

	// Returns the number of bytes already written into the response.
	// See Written()
	Buffered() int
}

// ResponseWriter interface is used by a handler to construct an protobuf response.
type ResponseWriter interface {
	BufFlusher

	// Set the response status code of the current request.
	SetStatus(statusCode int)

	// Returns the response status code of the current request.
	Status() int

	// Returns false if the server should close the connection after flush the data.
	KeepAlive() bool

	// Returns false if the server should close the connection after flush the data.
	SetKeepAlive(value bool)

	// Write the data into sending buffer.
	Write(data *any.Any) error
}

// responseWriter implements interface ResponseWriter
type responseWriter struct {
	writer    io.Writer
	status    int
	keepAlive bool
}

func NewResponseWriter(w io.Writer) *responseWriter {
	rw := &responseWriter{}
	rw.writer = w
	rw.keepAlive = true
	rw.status = defaultStatus
	return rw
}

func (rw *responseWriter) SetStatus(code int) {
	rw.status = code
}

func (rw *responseWriter) Status() int {
	return rw.status
}

func (rw *responseWriter) KeepAlive() bool {
	return rw.keepAlive
}

func (rw *responseWriter) SetKeepAlive(value bool) {
	rw.keepAlive = value
}

func (rw *responseWriter) Buffered() int {
	if w, ok := rw.writer.(BufFlusher); ok {
		return w.Buffered()
	}
	return noWritten
}

func (rw *responseWriter) Flush() error {
	if w, ok := rw.writer.(BufFlusher); ok {
		return w.Flush()
	}
	return ErrNotFlusher
}

func (rw *responseWriter) Write(msg *any.Any) error {
  buf, err := proto.Marshal(msg)
  if err != nil {
    return err
  }

  n, err := rw.writer.Write(buf)
  if err == nil && n != len(buf) {
    err = io.ErrShortWrite
  }

  return err
}

type respRecorder struct {
	responseWriter
	Message *any.Any
}

func (rr *respRecorder) Write(msg *any.Any) error {
	rr.Message = msg

	if rr.writer != nil {
    buf, err := proto.Marshal(msg)
    if err != nil {
      return err
    }

    n, err := rr.writer.Write(buf)
    if err == nil && n != len(buf) {
      err = io.ErrShortWrite
    }

    return err
	}
	return nil
}
