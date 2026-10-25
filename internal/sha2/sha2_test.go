package sha2

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"math/rand"
	"testing"
)

func TestKnownAnswers(t *testing.T) {
	million := make([]byte, 1000000)
	for i := range million {
		million[i] = 'a'
	}
	cases := []struct {
		name string
		f    func([]byte) []byte
		in   []byte
		want string
	}{
		{"sha256 empty", Sum256, nil, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
		{"sha256 abc", Sum256, []byte("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
		{"sha256 two blocks", Sum256, []byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
		{"sha256 million a", Sum256, million, "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
		{"sha384 abc", Sum384, []byte("abc"), "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"},
		{"sha512 abc", Sum512, []byte("abc"), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"},
		{"sha512 two blocks", Sum512, []byte("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"), "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(c.f(c.in)); got != c.want {
			t.Errorf("%s: got %s want %s", c.name, got, c.want)
		}
	}
}

// Every length from 0 to 300 bytes, written in random chunks, against the
// standard library.
func TestAgainstStdlib(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	pairs := []struct {
		ours, std func() hash.Hash
	}{{New256, sha256.New}, {New384, sha512.New384}, {New512, sha512.New}}
	for _, p := range pairs {
		for n := 0; n <= 300; n++ {
			data := make([]byte, n)
			r.Read(data)
			ours, std := p.ours(), p.std()
			for rest := data; len(rest) > 0; {
				k := r.Intn(len(rest)) + 1
				ours.Write(rest[:k])
				rest = rest[k:]
			}
			std.Write(data)
			if hex.EncodeToString(ours.Sum(nil)) != hex.EncodeToString(std.Sum(nil)) {
				t.Fatalf("size %d, length %d differs from the standard library", ours.Size(), n)
			}
		}
	}
}

func TestSumDoesNotDisturbState(t *testing.T) {
	h := New256()
	h.Write([]byte("ab"))
	h.Sum(nil)
	h.Write([]byte("c"))
	if hex.EncodeToString(h.Sum(nil)) != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
		t.Fatal("Sum changed the running hash")
	}
}
