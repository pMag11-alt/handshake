// Package rsa implements RSA signatures (RFC 8017): PKCS #1 v1.5 for
// certificate chains and RSA-PSS for TLS 1.3 CertificateVerify, plus key
// generation. Like the NIST curves it uses math/big, which is not
// constant-time.
package rsa

import (
	"bytes"
	"crypto/rand"
	"errors"
	"hash"
	"math/big"

	"github.com/pMag11-alt/handshake/internal/sha2"
)

type PublicKey struct {
	N *big.Int
	E int
}

type PrivateKey struct {
	PublicKey
	D, P, Q      *big.Int
	Dp, Dq, QInv *big.Int // CRT parameters
}

// Size is the modulus length in bytes.
func (k *PublicKey) Size() int { return (k.N.BitLen() + 7) / 8 }

var ErrVerification = errors.New("rsa: verification error")

// Hash identifies a digest for PKCS #1 v1.5 DigestInfo and for PSS.
type Hash struct {
	New        func() hash.Hash
	digestInfo []byte // DER prefix of DigestInfo, before the digest itself
}

var (
	SHA256 = Hash{sha2.New256, []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}}
	SHA384 = Hash{sha2.New384, []byte{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30}}
	SHA512 = Hash{sha2.New512, []byte{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40}}
)

func (k *PublicKey) encrypt(sig []byte) ([]byte, error) {
	s := new(big.Int).SetBytes(sig)
	if len(sig) != k.Size() || s.Cmp(k.N) >= 0 {
		return nil, ErrVerification
	}
	m := new(big.Int).Exp(s, big.NewInt(int64(k.E)), k.N)
	return m.FillBytes(make([]byte, k.Size())), nil
}

// decrypt is RSASP1 using the Chinese remainder theorem, checked against
// the public operation so a faulty result is never released.
func (k *PrivateKey) decrypt(em []byte) ([]byte, error) {
	m := new(big.Int).SetBytes(em)
	m1 := new(big.Int).Exp(m, k.Dp, k.P)
	m2 := new(big.Int).Exp(m, k.Dq, k.Q)
	h := new(big.Int).Sub(m1, m2)
	h.Mul(h, k.QInv)
	h.Mod(h, k.P)
	s := new(big.Int).Mul(h, k.Q)
	s.Add(s, m2)
	check := new(big.Int).Exp(s, big.NewInt(int64(k.E)), k.N)
	if check.Cmp(m) != 0 {
		return nil, errors.New("rsa: internal error")
	}
	return s.FillBytes(make([]byte, k.Size())), nil
}

func (h Hash) pkcs1Encoded(digest []byte, size int) ([]byte, error) {
	t := append(append([]byte(nil), h.digestInfo...), digest...)
	if size < len(t)+11 {
		return nil, errors.New("rsa: key too small")
	}
	em := make([]byte, size)
	em[1] = 1
	for i := 2; i < size-len(t)-1; i++ {
		em[i] = 0xff
	}
	copy(em[size-len(t):], t)
	return em, nil
}

// VerifyPKCS1v15 checks an RSASSA-PKCS1-v1_5 signature over digest.
func VerifyPKCS1v15(pub *PublicKey, h Hash, digest, sig []byte) error {
	em, err := pub.encrypt(sig)
	if err != nil {
		return err
	}
	want, err := h.pkcs1Encoded(digest, pub.Size())
	if err != nil {
		return err
	}
	// Compare the whole encoding rather than parsing it, which rules out
	// the classic lenient-parser signature forgeries.
	if !bytes.Equal(em, want) {
		return ErrVerification
	}
	return nil
}

// SignPKCS1v15 signs digest with RSASSA-PKCS1-v1_5.
func SignPKCS1v15(priv *PrivateKey, h Hash, digest []byte) ([]byte, error) {
	em, err := h.pkcs1Encoded(digest, priv.Size())
	if err != nil {
		return nil, err
	}
	return priv.decrypt(em)
}

func mgf1(h func() hash.Hash, seed []byte, length int) []byte {
	var out []byte
	for counter := uint32(0); len(out) < length; counter++ {
		d := h()
		d.Write(seed)
		d.Write([]byte{byte(counter >> 24), byte(counter >> 16), byte(counter >> 8), byte(counter)})
		out = d.Sum(out)
	}
	return out[:length]
}

func pssHash(h func() hash.Hash, digest, salt []byte) []byte {
	d := h()
	d.Write(make([]byte, 8))
	d.Write(digest)
	d.Write(salt)
	return d.Sum(nil)
}

// SignPSS signs digest with RSASSA-PSS, MGF1 with the same hash and a salt
// as long as the digest, the parameters TLS 1.3 requires.
func SignPSS(priv *PrivateKey, h Hash, digest []byte) ([]byte, error) {
	hLen := h.New().Size()
	emBits := priv.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	if emLen < 2*hLen+2 {
		return nil, errors.New("rsa: key too small for PSS")
	}
	salt := make([]byte, hLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	mHash := pssHash(h.New, digest, salt)
	db := make([]byte, emLen-hLen-1)
	db[len(db)-hLen-1] = 1
	copy(db[len(db)-hLen:], salt)
	mask := mgf1(h.New, mHash, len(db))
	for i := range db {
		db[i] ^= mask[i]
	}
	db[0] &= 0xff >> (8*emLen - emBits)
	em := append(append(db, mHash...), 0xbc)
	full := make([]byte, priv.Size())
	copy(full[len(full)-len(em):], em)
	return priv.decrypt(full)
}

// VerifyPSS checks an RSASSA-PSS signature with salt length equal to the
// digest length.
func VerifyPSS(pub *PublicKey, h Hash, digest, sig []byte) error {
	hLen := h.New().Size()
	full, err := pub.encrypt(sig)
	if err != nil {
		return err
	}
	emBits := pub.N.BitLen() - 1
	emLen := (emBits + 7) / 8
	em := full[len(full)-emLen:]
	if len(full) > emLen && full[0] != 0 {
		return ErrVerification
	}
	if emLen < 2*hLen+2 || em[len(em)-1] != 0xbc {
		return ErrVerification
	}
	db := append([]byte(nil), em[:emLen-hLen-1]...)
	mHash := em[emLen-hLen-1 : emLen-1]
	if db[0]&^(0xff>>(8*emLen-emBits)) != 0 {
		return ErrVerification
	}
	mask := mgf1(h.New, mHash, len(db))
	for i := range db {
		db[i] ^= mask[i]
	}
	db[0] &= 0xff >> (8*emLen - emBits)
	ps := len(db) - hLen - 1
	for i := 0; i < ps; i++ {
		if db[i] != 0 {
			return ErrVerification
		}
	}
	if db[ps] != 1 {
		return ErrVerification
	}
	salt := db[ps+1:]
	if !bytes.Equal(pssHash(h.New, digest, salt), mHash) {
		return ErrVerification
	}
	return nil
}

// GenerateKey creates a key with public exponent 65537.
func GenerateKey(bits int) (*PrivateKey, error) {
	e := big.NewInt(65537)
	one := big.NewInt(1)
	for {
		p, err := randomPrime(bits / 2)
		if err != nil {
			return nil, err
		}
		q, err := randomPrime(bits - bits/2)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) == 0 {
			continue
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != bits {
			continue
		}
		pm1 := new(big.Int).Sub(p, one)
		qm1 := new(big.Int).Sub(q, one)
		phi := new(big.Int).Mul(pm1, qm1)
		d := new(big.Int).ModInverse(e, phi)
		if d == nil {
			continue
		}
		if p.Cmp(q) < 0 {
			p, q = q, p
			pm1, qm1 = qm1, pm1
		}
		return &PrivateKey{
			PublicKey: PublicKey{N: n, E: 65537},
			D:         d,
			P:         p,
			Q:         q,
			Dp:        new(big.Int).Mod(d, pm1),
			Dq:        new(big.Int).Mod(d, qm1),
			QInv:      new(big.Int).ModInverse(q, p),
		}, nil
	}
}

// randomPrime returns a prime with exactly bits bits and the top two set,
// so the product of two of them has the full length.
func randomPrime(bits int) (*big.Int, error) {
	buf := make([]byte, (bits+7)/8)
	for {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		p := new(big.Int).SetBytes(buf)
		p.SetBit(p, bits-1, 1)
		p.SetBit(p, bits-2, 1)
		p.SetBit(p, 0, 1)
		for i := bits; i < len(buf)*8; i++ {
			p.SetBit(p, i, 0)
		}
		if p.ProbablyPrime(20) {
			return p, nil
		}
	}
}
