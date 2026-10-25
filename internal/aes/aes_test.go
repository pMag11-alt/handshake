package aes

import (
	"bytes"
	stdaes "crypto/aes"
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

// FIPS 197 appendix C.
func TestFIPS197(t *testing.T) {
	pt := unhex("00112233445566778899aabbccddeeff")
	cases := map[string]string{
		"000102030405060708090a0b0c0d0e0f":                                 "69c4e0d86a7b0430d8cdb78070b4c55a",
		"000102030405060708090a0b0c0d0e0f1011121314151617":                 "dda97ca4864cdfe06eaf70a0ec0d7191",
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f": "8ea2b7ca516745bfeafc49904b496089",
	}
	for key, want := range cases {
		b, err := New(unhex(key))
		if err != nil {
			t.Fatal(err)
		}
		out := make([]byte, 16)
		b.Encrypt(out, pt)
		if hex.EncodeToString(out) != want {
			t.Errorf("key %s: got %x", key, out)
		}
	}
}

func TestSboxSpotChecks(t *testing.T) {
	if sbox[0x00] != 0x63 || sbox[0x53] != 0xed || sbox[0xff] != 0x16 {
		t.Fatalf("sbox: %02x %02x %02x", sbox[0], sbox[0x53], sbox[0xff])
	}
}

func TestAgainstStdlib(t *testing.T) {
	r := rand.New(rand.NewSource(3))
	for _, size := range []int{16, 24, 32} {
		for i := 0; i < 200; i++ {
			key := make([]byte, size)
			pt := make([]byte, 16)
			r.Read(key)
			r.Read(pt)
			ours, _ := New(key)
			std, _ := stdaes.NewCipher(key)
			a, b := make([]byte, 16), make([]byte, 16)
			ours.Encrypt(a, pt)
			std.Encrypt(b, pt)
			if !bytes.Equal(a, b) {
				t.Fatalf("AES-%d mismatch", size*8)
			}
		}
	}
}
