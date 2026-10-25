// Package ecc implements the NIST prime curves P-256 and P-384: ECDH key
// agreement and ECDSA signatures with deterministic nonces (RFC 6979).
//
// Arithmetic uses math/big in Jacobian coordinates. math/big is not
// constant-time, so unlike the X25519 code this is not hardened against
// timing attacks. TLS only needs these curves to verify certificates (public
// data) and as a fallback key exchange for servers without X25519.
package ecc

import (
	"crypto/rand"
	"errors"
	"hash"
	"math/big"

	"github.com/pMag11-alt/handshake/internal/hmac"
)

// Curve holds the domain parameters of y^2 = x^3 - 3x + b over GF(p).
type Curve struct {
	Name    string
	P, N, B *big.Int
	Gx, Gy  *big.Int
	Bytes   int // size of a field element and of a scalar
}

func mustHex(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("ecc: bad constant")
	}
	return v
}

var P256 = &Curve{
	Name:  "P-256",
	P:     mustHex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
	N:     mustHex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
	B:     mustHex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
	Gx:    mustHex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
	Gy:    mustHex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
	Bytes: 32,
}

var P384 = &Curve{
	Name:  "P-384",
	P:     mustHex("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff"),
	N:     mustHex("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
	B:     mustHex("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
	Gx:    mustHex("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7"),
	Gy:    mustHex("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
	Bytes: 48,
}

// IsOnCurve reports whether (x, y) satisfies the curve equation.
func (c *Curve) IsOnCurve(x, y *big.Int) bool {
	if x.Sign() < 0 || x.Cmp(c.P) >= 0 || y.Sign() < 0 || y.Cmp(c.P) >= 0 {
		return false
	}
	lhs := new(big.Int).Mul(y, y)
	lhs.Mod(lhs, c.P)
	rhs := new(big.Int).Mul(x, x)
	rhs.Mul(rhs, x)
	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)
	rhs.Sub(rhs, threeX)
	rhs.Add(rhs, c.B)
	rhs.Mod(rhs, c.P)
	return lhs.Cmp(rhs) == 0
}

// jacobian is (X : Y : Z) representing the affine point (X/Z^2, Y/Z^3);
// Z = 0 is the point at infinity.
type jacobian struct{ x, y, z *big.Int }

func (c *Curve) mod(v *big.Int) *big.Int { return v.Mod(v, c.P) }

func (c *Curve) double(p jacobian) jacobian {
	if p.z.Sign() == 0 || p.y.Sign() == 0 {
		return jacobian{new(big.Int), new(big.Int), new(big.Int)}
	}
	// dbl-2001-b, valid because a = -3.
	delta := c.mod(new(big.Int).Mul(p.z, p.z))
	gamma := c.mod(new(big.Int).Mul(p.y, p.y))
	beta := c.mod(new(big.Int).Mul(p.x, gamma))
	alpha := new(big.Int).Sub(p.x, delta)
	t := new(big.Int).Add(p.x, delta)
	alpha.Mul(alpha, t)
	alpha.Mul(alpha, big.NewInt(3))
	c.mod(alpha)

	x3 := new(big.Int).Mul(alpha, alpha)
	x3.Sub(x3, new(big.Int).Lsh(beta, 3))
	c.mod(x3)

	z3 := new(big.Int).Add(p.y, p.z)
	z3.Mul(z3, z3)
	z3.Sub(z3, gamma)
	z3.Sub(z3, delta)
	c.mod(z3)

	y3 := new(big.Int).Lsh(beta, 2)
	y3.Sub(y3, x3)
	y3.Mul(y3, alpha)
	g2 := new(big.Int).Mul(gamma, gamma)
	y3.Sub(y3, g2.Lsh(g2, 3))
	c.mod(y3)
	return jacobian{x3, y3, z3}
}

func (c *Curve) add(p, q jacobian) jacobian {
	if p.z.Sign() == 0 {
		return q
	}
	if q.z.Sign() == 0 {
		return p
	}
	// add-2007-bl.
	z1z1 := c.mod(new(big.Int).Mul(p.z, p.z))
	z2z2 := c.mod(new(big.Int).Mul(q.z, q.z))
	u1 := c.mod(new(big.Int).Mul(p.x, z2z2))
	u2 := c.mod(new(big.Int).Mul(q.x, z1z1))
	s1 := c.mod(new(big.Int).Mul(p.y, new(big.Int).Mul(q.z, z2z2)))
	s2 := c.mod(new(big.Int).Mul(q.y, new(big.Int).Mul(p.z, z1z1)))
	h := c.mod(new(big.Int).Sub(u2, u1))
	r := c.mod(new(big.Int).Sub(s2, s1))
	if h.Sign() == 0 {
		if r.Sign() == 0 {
			return c.double(p)
		}
		return jacobian{new(big.Int), new(big.Int), new(big.Int)}
	}
	r.Lsh(r, 1)
	i := new(big.Int).Lsh(h, 1)
	i.Mul(i, i)
	c.mod(i)
	j := c.mod(new(big.Int).Mul(h, i))
	v := c.mod(new(big.Int).Mul(u1, i))

	x3 := new(big.Int).Mul(r, r)
	x3.Sub(x3, j)
	x3.Sub(x3, new(big.Int).Lsh(v, 1))
	c.mod(x3)

	y3 := new(big.Int).Sub(v, x3)
	y3.Mul(y3, r)
	t := new(big.Int).Mul(s1, j)
	y3.Sub(y3, t.Lsh(t, 1))
	c.mod(y3)

	z3 := new(big.Int).Add(p.z, q.z)
	z3.Mul(z3, z3)
	z3.Sub(z3, z1z1)
	z3.Sub(z3, z2z2)
	z3.Mul(z3, h)
	c.mod(z3)
	return jacobian{x3, y3, z3}
}

func (c *Curve) affine(p jacobian) (x, y *big.Int, ok bool) {
	if p.z.Sign() == 0 {
		return nil, nil, false
	}
	zinv := new(big.Int).ModInverse(p.z, c.P)
	zinv2 := c.mod(new(big.Int).Mul(zinv, zinv))
	x = c.mod(new(big.Int).Mul(p.x, zinv2))
	y = c.mod(new(big.Int).Mul(p.y, c.mod(new(big.Int).Mul(zinv2, zinv))))
	return x, y, true
}

func (c *Curve) scalarMult(x, y *big.Int, k *big.Int) jacobian {
	acc := jacobian{new(big.Int), new(big.Int), new(big.Int)}
	pt := jacobian{x, y, big.NewInt(1)}
	for i := k.BitLen() - 1; i >= 0; i-- {
		acc = c.double(acc)
		if k.Bit(i) == 1 {
			acc = c.add(acc, pt)
		}
	}
	return acc
}

// PublicKey is an affine point on a curve.
type PublicKey struct {
	Curve *Curve
	X, Y  *big.Int
}

// Bytes returns the uncompressed SEC 1 encoding 0x04 || X || Y.
func (k *PublicKey) Bytes() []byte {
	out := make([]byte, 1+2*k.Curve.Bytes)
	out[0] = 4
	k.X.FillBytes(out[1 : 1+k.Curve.Bytes])
	k.Y.FillBytes(out[1+k.Curve.Bytes:])
	return out
}

// ParsePublicKey decodes an uncompressed point and checks it is on the curve.
func ParsePublicKey(c *Curve, data []byte) (*PublicKey, error) {
	if len(data) != 1+2*c.Bytes || data[0] != 4 {
		return nil, errors.New("ecc: expected an uncompressed point")
	}
	x := new(big.Int).SetBytes(data[1 : 1+c.Bytes])
	y := new(big.Int).SetBytes(data[1+c.Bytes:])
	if !c.IsOnCurve(x, y) {
		return nil, errors.New("ecc: point is not on the curve")
	}
	return &PublicKey{Curve: c, X: x, Y: y}, nil
}

// PrivateKey is a scalar in [1, n-1] with its public point.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

// GenerateKey draws a private scalar from the operating system's CSPRNG.
func GenerateKey(c *Curve) (*PrivateKey, error) {
	buf := make([]byte, c.Bytes+8)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	// Reducing 64 extra bits keeps the bias negligible.
	d := new(big.Int).SetBytes(buf)
	nMinus1 := new(big.Int).Sub(c.N, big.NewInt(1))
	d.Mod(d, nMinus1)
	d.Add(d, big.NewInt(1))
	return NewPrivateKey(c, d), nil
}

// NewPrivateKey derives the public point for scalar d.
func NewPrivateKey(c *Curve, d *big.Int) *PrivateKey {
	x, y, _ := c.affine(c.scalarMult(c.Gx, c.Gy, d))
	return &PrivateKey{PublicKey: PublicKey{Curve: c, X: x, Y: y}, D: d}
}

// ECDH returns the x-coordinate of d * peer, the TLS shared secret.
func (k *PrivateKey) ECDH(peer *PublicKey) ([]byte, error) {
	if peer.Curve != k.Curve || !k.Curve.IsOnCurve(peer.X, peer.Y) {
		return nil, errors.New("ecc: invalid peer key")
	}
	x, _, ok := k.Curve.affine(k.Curve.scalarMult(peer.X, peer.Y, k.D))
	if !ok {
		return nil, errors.New("ecc: shared point is at infinity")
	}
	return x.FillBytes(make([]byte, k.Curve.Bytes)), nil
}

// hashToInt keeps the leftmost bitlen(n) bits of the digest.
func (c *Curve) hashToInt(digest []byte) *big.Int {
	nBits := c.N.BitLen()
	if len(digest) > (nBits+7)/8 {
		digest = digest[:(nBits+7)/8]
	}
	e := new(big.Int).SetBytes(digest)
	if excess := len(digest)*8 - nBits; excess > 0 {
		e.Rsh(e, uint(excess))
	}
	return e
}

// Verify checks an ECDSA signature (r, s) over a message digest.
func Verify(pub *PublicKey, digest []byte, r, s *big.Int) bool {
	c := pub.Curve
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(c.N) >= 0 || s.Cmp(c.N) >= 0 {
		return false
	}
	e := c.hashToInt(digest)
	w := new(big.Int).ModInverse(s, c.N)
	u1 := new(big.Int).Mul(e, w)
	u1.Mod(u1, c.N)
	u2 := new(big.Int).Mul(r, w)
	u2.Mod(u2, c.N)
	sum := c.add(c.scalarMult(c.Gx, c.Gy, u1), c.scalarMult(pub.X, pub.Y, u2))
	x, _, ok := c.affine(sum)
	if !ok {
		return false
	}
	return x.Mod(x, c.N).Cmp(r) == 0
}

// Sign produces an ECDSA signature with the nonce derived from the key and
// digest by RFC 6979, so no randomness is needed and nonces never repeat.
// h is the hash used for HMAC-DRBG (the one that produced digest).
func Sign(priv *PrivateKey, digest []byte, h func() hash.Hash) (r, s *big.Int) {
	c := priv.Curve
	e := c.hashToInt(digest)
	for k := range rfc6979(c, priv.D, digest, h) {
		x, _, _ := c.affine(c.scalarMult(c.Gx, c.Gy, k))
		r = new(big.Int).Mod(x, c.N)
		if r.Sign() == 0 {
			continue
		}
		kinv := new(big.Int).ModInverse(k, c.N)
		s = new(big.Int).Mul(priv.D, r)
		s.Add(s, e)
		s.Mul(s, kinv)
		s.Mod(s, c.N)
		if s.Sign() != 0 {
			return r, s
		}
	}
	panic("unreachable")
}

// rfc6979 yields candidate nonces from HMAC-DRBG seeded with the private
// key and the reduced digest.
func rfc6979(c *Curve, d *big.Int, digest []byte, h func() hash.Hash) func(yield func(*big.Int) bool) {
	return func(yield func(*big.Int) bool) {
		qlen := c.N.BitLen()
		rlen := (qlen + 7) / 8
		x := d.FillBytes(make([]byte, rlen))
		z := c.hashToInt(digest)
		z.Mod(z, c.N)
		h1 := z.FillBytes(make([]byte, rlen))

		size := h().Size()
		v := make([]byte, size)
		k := make([]byte, size)
		for i := range v {
			v[i] = 1
		}
		mac := func(key []byte, parts ...[]byte) []byte {
			m := hmac.New(h, key)
			for _, p := range parts {
				m.Write(p)
			}
			return m.Sum(nil)
		}
		k = mac(k, v, []byte{0}, x, h1)
		v = mac(k, v)
		k = mac(k, v, []byte{1}, x, h1)
		v = mac(k, v)
		for {
			var t []byte
			for len(t)*8 < qlen {
				v = mac(k, v)
				t = append(t, v...)
			}
			cand := new(big.Int).SetBytes(t[:rlen])
			if excess := rlen*8 - qlen; excess > 0 {
				cand.Rsh(cand, uint(excess))
			}
			if cand.Sign() > 0 && cand.Cmp(c.N) < 0 {
				if !yield(cand) {
					return
				}
			}
			k = mac(k, v, []byte{0})
			v = mac(k, v)
		}
	}
}
