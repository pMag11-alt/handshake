// Package x25519 implements the X25519 Diffie-Hellman function (RFC 7748).
//
// Field elements mod p = 2^255 - 19 are five 51-bit limbs. Products are
// accumulated in 128 bits and the top reduces into the bottom times 19,
// since 2^255 = 19 (mod p). The Montgomery ladder runs a fixed 255 steps
// with a branch-free conditional swap, so timing does not depend on the
// secret scalar.
package x25519

import (
	"encoding/binary"
	"errors"
	"math/bits"
)

const (
	ScalarSize = 32
	PointSize  = 32
	mask51     = 1<<51 - 1
)

type fe [5]uint64

type u128 struct{ lo, hi uint64 }

func mul64(a, b uint64) u128 {
	hi, lo := bits.Mul64(a, b)
	return u128{lo, hi}
}

func add128(a, b u128) u128 {
	lo, c := bits.Add64(a.lo, b.lo, 0)
	hi, _ := bits.Add64(a.hi, b.hi, c)
	return u128{lo, hi}
}

func shr51(a u128) uint64 { return a.hi<<13 | a.lo>>51 }

func feFromBytes(b []byte) fe {
	return fe{
		binary.LittleEndian.Uint64(b[0:]) & mask51,
		binary.LittleEndian.Uint64(b[6:]) >> 3 & mask51,
		binary.LittleEndian.Uint64(b[12:]) >> 6 & mask51,
		binary.LittleEndian.Uint64(b[19:]) >> 1 & mask51,
		binary.LittleEndian.Uint64(b[24:]) >> 12 & mask51, // drops bit 255
	}
}

// carry brings every limb back under 2^51 (plus a tiny excess in limb 0).
func (v *fe) carry() {
	c0 := v[0] >> 51
	c1 := v[1] >> 51
	c2 := v[2] >> 51
	c3 := v[3] >> 51
	c4 := v[4] >> 51
	v[0] = v[0]&mask51 + c4*19
	v[1] = v[1]&mask51 + c0
	v[2] = v[2]&mask51 + c1
	v[3] = v[3]&mask51 + c2
	v[4] = v[4]&mask51 + c3
}

func (v fe) bytes() [32]byte {
	v.carry()
	// Subtract p if v >= p: q is 1 exactly when v + 19 overflows 2^255.
	q := (v[0] + 19) >> 51
	q = (v[1] + q) >> 51
	q = (v[2] + q) >> 51
	q = (v[3] + q) >> 51
	q = (v[4] + q) >> 51
	v[0] += 19 * q
	v[1] += v[0] >> 51
	v[0] &= mask51
	v[2] += v[1] >> 51
	v[1] &= mask51
	v[3] += v[2] >> 51
	v[2] &= mask51
	v[4] += v[3] >> 51
	v[3] &= mask51
	v[4] &= mask51

	var out [32]byte
	binary.LittleEndian.PutUint64(out[0:], v[0]|v[1]<<51)
	binary.LittleEndian.PutUint64(out[8:], v[1]>>13|v[2]<<38)
	binary.LittleEndian.PutUint64(out[16:], v[2]>>26|v[3]<<25)
	binary.LittleEndian.PutUint64(out[24:], v[3]>>39|v[4]<<12)
	return out
}

func feAdd(a, b fe) fe {
	v := fe{a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3], a[4] + b[4]}
	v.carry()
	return v
}

// feSub adds 2p first so no limb goes negative.
func feSub(a, b fe) fe {
	v := fe{
		a[0] + 0xFFFFFFFFFFFDA - b[0],
		a[1] + 0xFFFFFFFFFFFFE - b[1],
		a[2] + 0xFFFFFFFFFFFFE - b[2],
		a[3] + 0xFFFFFFFFFFFFE - b[3],
		a[4] + 0xFFFFFFFFFFFFE - b[4],
	}
	v.carry()
	return v
}

func feMul(a, b fe) fe {
	a0, a1, a2, a3, a4 := a[0], a[1], a[2], a[3], a[4]
	b0, b1, b2, b3, b4 := b[0], b[1], b[2], b[3], b[4]
	b1_19, b2_19, b3_19, b4_19 := b1*19, b2*19, b3*19, b4*19

	r0 := add128(add128(add128(add128(mul64(a0, b0), mul64(a1, b4_19)), mul64(a2, b3_19)), mul64(a3, b2_19)), mul64(a4, b1_19))
	r1 := add128(add128(add128(add128(mul64(a0, b1), mul64(a1, b0)), mul64(a2, b4_19)), mul64(a3, b3_19)), mul64(a4, b2_19))
	r2 := add128(add128(add128(add128(mul64(a0, b2), mul64(a1, b1)), mul64(a2, b0)), mul64(a3, b4_19)), mul64(a4, b3_19))
	r3 := add128(add128(add128(add128(mul64(a0, b3), mul64(a1, b2)), mul64(a2, b1)), mul64(a3, b0)), mul64(a4, b4_19))
	r4 := add128(add128(add128(add128(mul64(a0, b4), mul64(a1, b3)), mul64(a2, b2)), mul64(a3, b1)), mul64(a4, b0))

	c0, c1, c2, c3, c4 := shr51(r0), shr51(r1), shr51(r2), shr51(r3), shr51(r4)
	v := fe{
		r0.lo&mask51 + c4*19,
		r1.lo&mask51 + c0,
		r2.lo&mask51 + c1,
		r3.lo&mask51 + c2,
		r4.lo&mask51 + c3,
	}
	v.carry()
	return v
}

func feSquare(a fe) fe { return feMul(a, a) }

// feInvert computes a^(p-2) by square-and-multiply over p-2 = 2^255 - 21.
func feInvert(a fe) fe {
	exp := [32]byte{0xeb} // little-endian 2^255 - 21
	for i := 1; i < 31; i++ {
		exp[i] = 0xff
	}
	exp[31] = 0x7f
	r := fe{1}
	for i := 254; i >= 0; i-- {
		r = feSquare(r)
		if exp[i/8]>>(i%8)&1 == 1 {
			r = feMul(r, a)
		}
	}
	return r
}

// cswap swaps a and b when swap is 1, without branching.
func cswap(a, b *fe, swap uint64) {
	mask := -swap
	for i := range a {
		t := mask & (a[i] ^ b[i])
		a[i] ^= t
		b[i] ^= t
	}
}

var a24 = fe{121665}

// ladder computes scalar * u on the Montgomery curve.
func ladder(scalar *[32]byte, u fe) fe {
	x1 := u
	x2, z2 := fe{1}, fe{}
	x3, z3 := u, fe{1}
	var swap uint64
	for t := 254; t >= 0; t-- {
		bit := uint64(scalar[t/8]>>(t%8)) & 1
		swap ^= bit
		cswap(&x2, &x3, swap)
		cswap(&z2, &z3, swap)
		swap = bit

		a := feAdd(x2, z2)
		aa := feSquare(a)
		b := feSub(x2, z2)
		bb := feSquare(b)
		e := feSub(aa, bb)
		c := feAdd(x3, z3)
		d := feSub(x3, z3)
		da := feMul(d, a)
		cb := feMul(c, b)
		x3 = feSquare(feAdd(da, cb))
		z3 = feMul(x1, feSquare(feSub(da, cb)))
		x2 = feMul(aa, bb)
		z2 = feMul(e, feAdd(aa, feMul(a24, e)))
	}
	cswap(&x2, &x3, swap)
	cswap(&z2, &z3, swap)
	return feMul(x2, feInvert(z2))
}

// Basepoint is u = 9.
var Basepoint = [32]byte{9}

var ErrLowOrder = errors.New("x25519: shared secret is all zeros (low-order point)")

// X25519 returns scalar * point. It fails if the result is the all-zero
// value, which a peer can force by sending a low-order point.
func X25519(scalar, point []byte) ([]byte, error) {
	if len(scalar) != ScalarSize || len(point) != PointSize {
		return nil, errors.New("x25519: bad input length")
	}
	var k [32]byte
	copy(k[:], scalar)
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
	out := ladder(&k, feFromBytes(point)).bytes()
	var zero byte
	for _, b := range out {
		zero |= b
	}
	if zero == 0 {
		return nil, ErrLowOrder
	}
	return out[:], nil
}

// PublicKey derives the public key for a 32-byte private scalar.
func PublicKey(scalar []byte) ([]byte, error) {
	return X25519(scalar, Basepoint[:])
}
