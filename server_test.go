package robin

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/xtaci/kcp-go"
)

func TestListener(t *testing.T) {
  key := Key("demo_pass", "demo_salt")

  // start the server
  go ListenAndServe("localhost:12345", key, nil)
  time.Sleep(time.Millisecond * 10)

  blk, _ := kcp.NewAESBlockCrypt(key)
  sess, err := kcp.DialWithOptions("localhost:12345", blk, 10, 3)
  require.Nil(t, err)

  data := time.Now().String()
	// buf := make([]byte, len(data))
  _, err = sess.Write([]byte(data))
  require.Nil(t, err)
  time.Sleep(time.Millisecond * 10)
}
