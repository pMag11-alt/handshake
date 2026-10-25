package gcm

import (
	"bytes"
	stdaes "crypto/aes"
	"crypto/cipher"
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

// Test cases 2, 3 and 4 from the original GCM specification.
func TestSpecVectors(t *testing.T) {
	cases := []struct{ key, iv, pt, ad, ct, tag string }{
		{"00000000000000000000000000000000", "000000000000000000000000", "00000000000000000000000000000000", "",
			"0388dace60b6a392f328c2b971b2fe78", "ab6e47d42cec13bdf53a67b21257bddf"},
		{"feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
			"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "",
			"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
			"4d5c2af327cd64a62cf35abd2ba6fab4"},
		{"feffe9928665731c6d6a8f9467308308", "cafebabefacedbaddecaf888",
			"d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
			"feedfacedeadbeeffeedfacedeadbeefabaddad2",
			"42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
			"5bc94fbc3221a5db94fae95ae7121a47"},
	}
	for i, c := range cases {
		g, err := New(unhex(c.key))
		if err != nil {
			t.Fatal(err)
		}
		out := g.Seal(nil, unhex(c.iv), unhex(c.pt), unhex(c.ad))
		if want := c.ct + c.tag; hex.EncodeToString(out) != want {
			t.Errorf("case %d seal: got %x", i, out)
		}
		pt, err := g.Open(nil, unhex(c.iv), out, unhex(c.ad))
		if err != nil || hex.EncodeToString(pt) != c.pt {
			t.Errorf("case %d open: %v", i, err)
		}
	}
}

func TestAgainstStdlibAndTamper(t *testing.T) {
	r := rand.New(rand.NewSource(4))
	for _, size := range []int{16, 32} {
		for i := 0; i < 300; i++ {
			key, nonce := make([]byte, size), make([]byte, 12)
			pt, ad := make([]byte, r.Intn(200)), make([]byte, r.Intn(40))
			r.Read(key)
			r.Read(nonce)
			r.Read(pt)
			r.Read(ad)
			ours, _ := New(key)
			block, _ := stdaes.NewCipher(key)
			std, _ := cipher.NewGCM(block)
			a := ours.Seal([]byte("prefix"), nonce, pt, ad)
			b := std.Seal([]byte("prefix"), nonce, pt, ad)
			if !bytes.Equal(a, b) {
				t.Fatalf("AES-%d-GCM mismatch at length %d", size*8, len(pt))
			}
			ct := a[len("prefix"):]
			bad := append([]byte(nil), ct...)
			bad[r.Intn(len(bad))] ^= 1 << r.Intn(8)
			if _, err := ours.Open(nil, nonce, bad, ad); err == nil {
				t.Fatal("tampered ciphertext was accepted")
			}
		}
	}
}
