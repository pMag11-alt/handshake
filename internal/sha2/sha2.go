// Package sha2 implements SHA-256, SHA-384 and SHA-512 (FIPS 180-4).
//
// The digests satisfy hash.Hash, so HMAC, HKDF and the TLS transcript can
// treat them interchangeably.
package sha2

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

const (
	Size256 = 32
	Size384 = 48
	Size512 = 64

	blockSize256 = 64
	blockSize512 = 128
)

var k256 = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

var k512 = [80]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
}

// ---- SHA-256 -------------------------------------------------------------------

type digest256 struct {
	h   [8]uint32
	buf [blockSize256]byte
	n   int    // bytes in buf
	len uint64 // total bytes written
}

// New256 returns a SHA-256 hash.
func New256() hash.Hash { d := new(digest256); d.Reset(); return d }

func (d *digest256) Reset() {
	d.h = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	d.n = 0
	d.len = 0
}

func (d *digest256) Size() int      { return Size256 }
func (d *digest256) BlockSize() int { return blockSize256 }

func (d *digest256) Write(p []byte) (int, error) {
	written := len(p)
	d.len += uint64(len(p))
	if d.n > 0 {
		c := copy(d.buf[d.n:], p)
		d.n += c
		p = p[c:]
		if d.n == blockSize256 {
			block256(&d.h, d.buf[:])
			d.n = 0
		}
	}
	for len(p) >= blockSize256 {
		block256(&d.h, p[:blockSize256])
		p = p[blockSize256:]
	}
	d.n += copy(d.buf[:], p)
	return written, nil
}

func (d *digest256) Sum(in []byte) []byte {
	c := *d // Sum must not change the running state.
	var pad [blockSize256 + 8]byte
	pad[0] = 0x80
	// 0x80, zeros, then the 64-bit bit length, ending on a block boundary.
	padLen := blockSize256 - int((c.len+8)%blockSize256)
	binary.BigEndian.PutUint64(pad[padLen:], c.len*8)
	c.Write(pad[:padLen+8])
	out := make([]byte, Size256)
	for i, v := range c.h {
		binary.BigEndian.PutUint32(out[i*4:], v)
	}
	return append(in, out...)
}

func block256(h *[8]uint32, p []byte) {
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(p[i*4:])
	}
	for i := 16; i < 64; i++ {
		s0 := bits.RotateLeft32(w[i-15], -7) ^ bits.RotateLeft32(w[i-15], -18) ^ w[i-15]>>3
		s1 := bits.RotateLeft32(w[i-2], -17) ^ bits.RotateLeft32(w[i-2], -19) ^ w[i-2]>>10
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
	a, b, c, dd, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
	for i := 0; i < 64; i++ {
		S1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
		ch := (e & f) ^ (^e & g)
		t1 := hh + S1 + ch + k256[i] + w[i]
		S0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
		maj := (a & b) ^ (a & c) ^ (b & c)
		t2 := S0 + maj
		hh, g, f, e, dd, c, b, a = g, f, e, dd+t1, c, b, a, t1+t2
	}
	h[0] += a
	h[1] += b
	h[2] += c
	h[3] += dd
	h[4] += e
	h[5] += f
	h[6] += g
	h[7] += hh
}

// ---- SHA-512 and SHA-384 ---------------------------------------------------------

type digest512 struct {
	h    [8]uint64
	buf  [blockSize512]byte
	n    int
	len  uint64
	size int // 48 for SHA-384, 64 for SHA-512
}

// New512 returns a SHA-512 hash.
func New512() hash.Hash { d := &digest512{size: Size512}; d.Reset(); return d }

// New384 returns a SHA-384 hash: SHA-512 with different initial values,
// truncated to 48 bytes.
func New384() hash.Hash { d := &digest512{size: Size384}; d.Reset(); return d }

func (d *digest512) Reset() {
	if d.size == Size384 {
		d.h = [8]uint64{
			0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
			0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
		}
	} else {
		d.h = [8]uint64{
			0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
			0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
		}
	}
	d.n = 0
	d.len = 0
}

func (d *digest512) Size() int      { return d.size }
func (d *digest512) BlockSize() int { return blockSize512 }

func (d *digest512) Write(p []byte) (int, error) {
	written := len(p)
	d.len += uint64(len(p))
	if d.n > 0 {
		c := copy(d.buf[d.n:], p)
		d.n += c
		p = p[c:]
		if d.n == blockSize512 {
			block512(&d.h, d.buf[:])
			d.n = 0
		}
	}
	for len(p) >= blockSize512 {
		block512(&d.h, p[:blockSize512])
		p = p[blockSize512:]
	}
	d.n += copy(d.buf[:], p)
	return written, nil
}

func (d *digest512) Sum(in []byte) []byte {
	c := *d
	var pad [blockSize512 + 16]byte
	pad[0] = 0x80
	padLen := blockSize512 - int((c.len+16)%blockSize512)
	// The length field is 128 bits; messages here never exceed 2^61 bytes.
	binary.BigEndian.PutUint64(pad[padLen+8:], c.len*8)
	c.Write(pad[:padLen+16])
	out := make([]byte, Size512)
	for i, v := range c.h {
		binary.BigEndian.PutUint64(out[i*8:], v)
	}
	return append(in, out[:d.size]...)
}

func block512(h *[8]uint64, p []byte) {
	var w [80]uint64
	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint64(p[i*8:])
	}
	for i := 16; i < 80; i++ {
		s0 := bits.RotateLeft64(w[i-15], -1) ^ bits.RotateLeft64(w[i-15], -8) ^ w[i-15]>>7
		s1 := bits.RotateLeft64(w[i-2], -19) ^ bits.RotateLeft64(w[i-2], -61) ^ w[i-2]>>6
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
	a, b, c, dd, e, f, g, hh := h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]
	for i := 0; i < 80; i++ {
		S1 := bits.RotateLeft64(e, -14) ^ bits.RotateLeft64(e, -18) ^ bits.RotateLeft64(e, -41)
		ch := (e & f) ^ (^e & g)
		t1 := hh + S1 + ch + k512[i] + w[i]
		S0 := bits.RotateLeft64(a, -28) ^ bits.RotateLeft64(a, -34) ^ bits.RotateLeft64(a, -39)
		maj := (a & b) ^ (a & c) ^ (b & c)
		t2 := S0 + maj
		hh, g, f, e, dd, c, b, a = g, f, e, dd+t1, c, b, a, t1+t2
	}
	h[0] += a
	h[1] += b
	h[2] += c
	h[3] += dd
	h[4] += e
	h[5] += f
	h[6] += g
	h[7] += hh
}

// Sum256 returns the SHA-256 digest of data.
func Sum256(data []byte) []byte { h := New256(); h.Write(data); return h.Sum(nil) }

// Sum384 returns the SHA-384 digest of data.
func Sum384(data []byte) []byte { h := New384(); h.Write(data); return h.Sum(nil) }

// Sum512 returns the SHA-512 digest of data.
func Sum512(data []byte) []byte { h := New512(); h.Write(data); return h.Sum(nil) }
