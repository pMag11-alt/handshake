package hmac

import (
	"bytes"
	stdhmac "crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/pMag11-alt/handshake/internal/sha2"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// RFC 4231 test cases 1, 2 and 6 (key longer than the block size).
func TestRFC4231(t *testing.T) {
	cases := []struct{ key, data, sha256, sha512 string }{
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", hex.EncodeToString([]byte("Hi There")),
			"b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
			"87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
		},
		{
			hex.EncodeToString([]byte("Jefe")), hex.EncodeToString([]byte("what do ya want for nothing?")),
			"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
			"164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737",
		},
		{
			strings131aa(), hex.EncodeToString([]byte("Test Using Larger Than Block-Size Key - Hash Key First")),
			"60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
			"80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f3526b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
		},
	}
	for i, c := range cases {
		if got := hex.EncodeToString(Sum(sha2.New256, unhex(c.key), unhex(c.data))); got != c.sha256 {
			t.Errorf("case %d sha256: %s", i, got)
		}
		if got := hex.EncodeToString(Sum(sha2.New512, unhex(c.key), unhex(c.data))); got != c.sha512 {
			t.Errorf("case %d sha512: %s", i, got)
		}
	}
}

func strings131aa() string {
	return hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 131))
}

func TestResetAndAgainstStdlib(t *testing.T) {
	r := rand.New(rand.NewSource(2))
	for i := 0; i < 200; i++ {
		key := make([]byte, r.Intn(150))
		msg := make([]byte, r.Intn(300))
		r.Read(key)
		r.Read(msg)
		m := New(sha2.New256, key)
		m.Write([]byte("garbage"))
		m.Reset()
		m.Write(msg)
		std := stdhmac.New(sha256.New, key)
		std.Write(msg)
		if !Equal(m.Sum(nil), std.Sum(nil)) {
			t.Fatalf("mismatch for key length %d, message length %d", len(key), len(msg))
		}
	}
}
