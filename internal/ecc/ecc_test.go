package ecc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"math/big"
	"math/rand"
	"strings"
	"testing"

	"github.com/pMag11-alt/handshake/internal/sha2"
)

func hexInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(strings.ToLower(s), 16)
	if !ok {
		panic(s)
	}
	return v
}

// RFC 6979 appendix A.2.5: P-256, SHA-256, message "sample".
func TestRFC6979P256(t *testing.T) {
	priv := NewPrivateKey(P256, hexInt("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721"))
	if priv.X.Cmp(hexInt("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6")) != 0 ||
		priv.Y.Cmp(hexInt("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299")) != 0 {
		t.Fatalf("public key: %x %x", priv.X, priv.Y)
	}
	digest := sha2.Sum256([]byte("sample"))
	r, s := Sign(priv, digest, sha2.New256)
	if r.Cmp(hexInt("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716")) != 0 ||
		s.Cmp(hexInt("F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")) != 0 {
		t.Fatalf("signature: r=%x s=%x", r, s)
	}
	if !Verify(&priv.PublicKey, digest, r, s) {
		t.Fatal("own signature does not verify")
	}
	if Verify(&priv.PublicKey, sha2.Sum256([]byte("simple")), r, s) {
		t.Fatal("signature verified for a different message")
	}
}

func stdCurve(c *Curve) elliptic.Curve {
	if c == P256 {
		return elliptic.P256()
	}
	return elliptic.P384()
}

// Signatures cross-verify with crypto/ecdsa in both directions.
func TestECDSAAgainstStdlib(t *testing.T) {
	for _, c := range []*Curve{P256, P384} {
		var newHash func() hash.Hash
		var stdSum func([]byte) []byte
		if c == P256 {
			newHash, stdSum = sha2.New256, func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }
		} else {
			newHash, stdSum = sha2.New384, func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }
		}
		for i := 0; i < 10; i++ {
			priv, err := GenerateKey(c)
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte(strings.Repeat("handshake", i+1))
			digest := stdSum(msg)
			r, s := Sign(priv, digest, newHash)
			stdPub := &ecdsa.PublicKey{Curve: stdCurve(c), X: priv.X, Y: priv.Y}
			if !ecdsa.Verify(stdPub, digest, r, s) {
				t.Fatalf("%s: crypto/ecdsa rejects our signature", c.Name)
			}
			stdPriv := &ecdsa.PrivateKey{PublicKey: *stdPub, D: priv.D}
			r2, s2, err := ecdsa.Sign(rand.New(rand.NewSource(int64(i))), stdPriv, digest)
			if err != nil {
				t.Fatal(err)
			}
			if !Verify(&priv.PublicKey, digest, r2, s2) {
				t.Fatalf("%s: we reject crypto/ecdsa's signature", c.Name)
			}
		}
	}
}

func TestECDHAgainstStdlib(t *testing.T) {
	for _, pair := range []struct {
		ours *Curve
		std  ecdh.Curve
	}{{P256, ecdh.P256()}, {P384, ecdh.P384()}} {
		for i := 0; i < 5; i++ {
			a, _ := GenerateKey(pair.ours)
			stdB, _ := pair.std.GenerateKey(cryptoRand{})
			peer, err := ParsePublicKey(pair.ours, stdB.PublicKey().Bytes())
			if err != nil {
				t.Fatal(err)
			}
			ours, err := a.ECDH(peer)
			if err != nil {
				t.Fatal(err)
			}
			stdA, err := pair.std.NewPublicKey(a.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			theirs, _ := stdB.ECDH(stdA)
			if hex.EncodeToString(ours) != hex.EncodeToString(theirs) {
				t.Fatalf("%s: shared secrets differ", pair.ours.Name)
			}
		}
	}
}

func TestRejectsOffCurvePoints(t *testing.T) {
	priv, _ := GenerateKey(P256)
	enc := priv.Bytes()
	enc[len(enc)-1] ^= 1
	if _, err := ParsePublicKey(P256, enc); err == nil {
		t.Fatal("accepted a point that is not on the curve")
	}
}
