package rsa

import (
	"crypto"
	stdrsa "crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"testing"
)

var testKey *PrivateKey

func key(t *testing.T) *PrivateKey {
	t.Helper()
	if testKey == nil {
		k, err := GenerateKey(2048)
		if err != nil {
			t.Fatal(err)
		}
		testKey = k
	}
	return testKey
}

func toStd(k *PrivateKey) *stdrsa.PrivateKey {
	s := &stdrsa.PrivateKey{
		PublicKey: stdrsa.PublicKey{N: k.N, E: k.E},
		D:         k.D,
		Primes:    []*bigInt{k.P, k.Q},
	}
	s.Precompute()
	return s
}

func TestGeneratedKeyIsConsistent(t *testing.T) {
	k := key(t)
	if k.N.BitLen() != 2048 {
		t.Fatalf("modulus is %d bits", k.N.BitLen())
	}
	if err := toStd(k).Validate(); err != nil {
		t.Fatalf("crypto/rsa rejects the key: %v", err)
	}
}

func TestPKCS1v15AgainstStdlib(t *testing.T) {
	k := key(t)
	std := toStd(k)
	digest := sha256.Sum256([]byte("certificate body"))
	sig, err := SignPKCS1v15(k, SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if err := stdrsa.VerifyPKCS1v15(&std.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
		t.Fatalf("crypto/rsa rejects our signature: %v", err)
	}
	stdSig, _ := stdrsa.SignPKCS1v15(nil, std, crypto.SHA256, digest[:])
	if err := VerifyPKCS1v15(&k.PublicKey, SHA256, digest[:], stdSig); err != nil {
		t.Fatalf("we reject crypto/rsa's signature: %v", err)
	}
	stdSig[10] ^= 1
	if VerifyPKCS1v15(&k.PublicKey, SHA256, digest[:], stdSig) == nil {
		t.Fatal("accepted a corrupted signature")
	}
}

func TestPSSAgainstStdlib(t *testing.T) {
	k := key(t)
	std := toStd(k)
	opts := &stdrsa.PSSOptions{SaltLength: stdrsa.PSSSaltLengthEqualsHash}
	for _, c := range []struct {
		h   Hash
		std crypto.Hash
		sum func([]byte) []byte
	}{
		{SHA256, crypto.SHA256, func(b []byte) []byte { s := sha256.Sum256(b); return s[:] }},
		{SHA384, crypto.SHA384, func(b []byte) []byte { s := sha512.Sum384(b); return s[:] }},
	} {
		digest := c.sum([]byte("TLS 1.3, server CertificateVerify"))
		sig, err := SignPSS(k, c.h, digest)
		if err != nil {
			t.Fatal(err)
		}
		if err := stdrsa.VerifyPSS(&std.PublicKey, c.std, digest, sig, opts); err != nil {
			t.Fatalf("crypto/rsa rejects our PSS signature: %v", err)
		}
		stdSig, err := stdrsa.SignPSS(randReader{}, std, c.std, digest, opts)
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyPSS(&k.PublicKey, c.h, digest, stdSig); err != nil {
			t.Fatalf("we reject crypto/rsa's PSS signature: %v", err)
		}
		other := c.sum([]byte("something else"))
		if VerifyPSS(&k.PublicKey, c.h, other, stdSig) == nil {
			t.Fatal("PSS signature verified for the wrong digest")
		}
	}
}
