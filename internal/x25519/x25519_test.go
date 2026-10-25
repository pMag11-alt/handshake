package x25519

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"math/rand"
	"testing"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// RFC 7748 section 5.2.
func TestVectors(t *testing.T) {
	cases := []struct{ scalar, u, out string }{
		{"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
			"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
			"c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"},
		{"4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
			"e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
			"95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"},
	}
	for i, c := range cases {
		out, err := X25519(unhex(c.scalar), unhex(c.u))
		if err != nil || hex.EncodeToString(out) != c.out {
			t.Errorf("case %d: %x %v", i, out, err)
		}
	}
}

// RFC 7748 section 5.2, iterated: k, u = X25519(k, u), k.
func TestIterated(t *testing.T) {
	k := append([]byte(nil), Basepoint[:]...)
	u := append([]byte(nil), Basepoint[:]...)
	want := map[int]string{
		1:    "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
		1000: "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
	}
	n := 1000
	if testing.Short() {
		n = 1
	}
	for i := 1; i <= n; i++ {
		out, err := X25519(k, u)
		if err != nil {
			t.Fatal(err)
		}
		u, k = k, out
		if w, ok := want[i]; ok && hex.EncodeToString(k) != w {
			t.Fatalf("after %d iterations: %x", i, k)
		}
	}
}

// RFC 7748 section 6.1: both sides derive the same shared secret.
func TestDiffieHellman(t *testing.T) {
	alice := unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	bob := unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	alicePub, _ := PublicKey(alice)
	bobPub, _ := PublicKey(bob)
	if hex.EncodeToString(alicePub) != "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a" {
		t.Fatalf("alice public: %x", alicePub)
	}
	if hex.EncodeToString(bobPub) != "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f" {
		t.Fatalf("bob public: %x", bobPub)
	}
	s1, _ := X25519(alice, bobPub)
	s2, _ := X25519(bob, alicePub)
	if !bytes.Equal(s1, s2) || hex.EncodeToString(s1) != "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" {
		t.Fatalf("shared secret: %x / %x", s1, s2)
	}
}

func TestLowOrderPointRejected(t *testing.T) {
	scalar := unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	if _, err := X25519(scalar, make([]byte, 32)); err != ErrLowOrder {
		t.Fatalf("expected ErrLowOrder, got %v", err)
	}
}

func TestAgainstStdlib(t *testing.T) {
	r := rand.New(rand.NewSource(6))
	for i := 0; i < 200; i++ {
		a, b := make([]byte, 32), make([]byte, 32)
		r.Read(a)
		r.Read(b)
		stdA, _ := ecdh.X25519().NewPrivateKey(a)
		stdB, _ := ecdh.X25519().NewPrivateKey(b)
		want, _ := stdA.ECDH(stdB.PublicKey())
		got, err := X25519(a, stdB.PublicKey().Bytes())
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("case %d: got %x want %x", i, got, want)
		}
	}
}

// Non-canonical inputs: u >= p and the top bit set must be accepted and
// reduced, as RFC 7748 requires.
func TestNonCanonicalU(t *testing.T) {
	scalar := unhex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
	u := unhex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
	high := append([]byte(nil), u...)
	high[31] |= 0x80
	a, _ := X25519(scalar, u)
	b, _ := X25519(scalar, high)
	if !bytes.Equal(a, b) {
		t.Fatal("top bit of u was not ignored")
	}
}
