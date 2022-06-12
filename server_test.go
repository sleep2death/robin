package robin

import (
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/stretchr/testify/require"
	"github.com/xtaci/kcp-go"
)

func TestListener(t *testing.T) {
  key := Key("demo_pass", "demo_salt")

  // start the server
  go func() {
    err := ListenAndServe("localhost:12345", key, &tHandler{t: t})
    require.Nil(t, err)
  }()
  time.Sleep(time.Millisecond * 10)

  // dial to the server
  blk, _ := kcp.NewAESBlockCrypt(key)
  sess, err := kcp.DialWithOptions("localhost:12345", blk, 10, 3)
  require.Nil(t, err)

  msg := &any.Any{
		TypeUrl: "pb.Ping",
		Value:   []byte("ping"),
	}
  buf, err := proto.Marshal(msg)
  require.Nil(t, err)
  sess.Write(buf)
  time.Sleep(time.Millisecond * 10)

  b := make([]byte, 4096)
  n, err := sess.Read(b)
  require.Nil(t, err)

  res := new(any.Any)
  err = proto.Unmarshal(b[:n], res)
  require.Nil(t, err)
  require.Equal(t, "pb.Pong", res.TypeUrl)
  t.Logf("pong")

  // test default timeout
  time.Sleep(time.Millisecond * 10)
}

type tHandler struct {
  t *testing.T
}

func (h *tHandler) Serve(w ResponseWriter, req *Request) {
  switch req.TypeUrl {
  case "pb.Ping":
    h.t.Logf("ping")
    w.Write(&any.Any{TypeUrl: "pb.Pong", Value: []byte("pong")})
  case "pb.Pong":
    h.t.Logf("pong recv")
    w.Write(&any.Any{TypeUrl: "pb.Ping", Value: []byte("ping")})
  default:
    h.t.Fatalf("unknown request url")
  }
}
