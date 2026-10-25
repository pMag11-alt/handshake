package chacha20poly1305

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/pMag11-alt/handshake/internal/chacha20"
	"github.com/pMag11-alt/handshake/internal/poly1305"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

const sunscreen = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."

// RFC 8439 section 2.3.2.
func TestChaChaBlock(t *testing.T) {
	var key [32]byte
	copy(key[:], unhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"))
	var nonce [12]byte
	copy(nonce[:], unhex("000000090000004a00000000"))
	var out [64]byte
	chacha20.Block(&out, &key, 1, &nonce)
	want := "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4ed2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e"
	if hex.EncodeToString(out[:]) != want {
		t.Fatalf("block: %x", out)
	}
}

// RFC 8439 section 2.5.2.
func TestPoly1305(t *testing.T) {
	var key [32]byte
	copy(key[:], unhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"))
	tag := poly1305.Sum([]byte("Cryptographic Forum Research Group"), &key)
	if hex.EncodeToString(tag[:]) != "a8061dc1305136c6c22b8baf0c0127a9" {
		t.Fatalf("tag: %x", tag)
	}
}

// RFC 8439 section 2.8.2.
func TestAEAD(t *testing.T) {
	a, _ := New(unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"))
	nonce := unhex("070000004041424344454647")
	ad := unhex("50515253c0c1c2c3c4c5c6c7")
	out := a.Seal(nil, nonce, []byte(sunscreen), ad)
	wantCT := "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116"
	wantTag := "1ae10b594f09e26a7e902ecbd0600691"
	if hex.EncodeToString(out) != wantCT+wantTag {
		t.Fatalf("seal: %x", out)
	}
	pt, err := a.Open(nil, nonce, out, ad)
	if err != nil || string(pt) != sunscreen {
		t.Fatalf("open: %v", err)
	}
	out[0] ^= 1
	if _, err := a.Open(nil, nonce, out, ad); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

// Poly1305 edge cases from RFC 8439 appendix A.3: values that make the
// accumulator wrap around 2^130 - 5.
func TestPoly1305Wraparound(t *testing.T) {
	cases := []struct{ key, msg, tag string }{
		{"02000000000000000000000000000000 00000000000000000000000000000000",
			"ffffffffffffffffffffffffffffffff", "03000000000000000000000000000000"},
		{"02000000000000000000000000000000 ffffffffffffffffffffffffffffffff",
			"02000000000000000000000000000000", "03000000000000000000000000000000"},
		{"01000000000000000000000000000000 00000000000000000000000000000000",
			"ffffffffffffffffffffffffffffffff f0ffffffffffffffffffffffffffffff 11000000000000000000000000000000",
			"05000000000000000000000000000000"},
		{"01000000000000000000000000000000 00000000000000000000000000000000",
			"ffffffffffffffffffffffffffffffff fbfefefefefefefefefefefefefefefe 01010101010101010101010101010101",
			"00000000000000000000000000000000"},
		{"02000000000000000000000000000000 00000000000000000000000000000000",
			"fdffffffffffffffffffffffffffffff", "faffffffffffffffffffffffffffffff"},
	}
	for i, c := range cases {
		var key [32]byte
		copy(key[:], unhex(c.key))
		tag := poly1305.Sum(unhex(c.msg), &key)
		if hex.EncodeToString(tag[:]) != c.tag {
			t.Errorf("case %d: %x", i, tag)
		}
	}
}
