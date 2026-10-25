// Package gcm implements AES-GCM authenticated encryption (NIST SP 800-38D)
// with the 12-byte nonces TLS uses.
//
// GHASH multiplies in GF(2^128) four bits at a time against a table of 16
// precomputed multiples of the hash key, as in Shoup's method.
package gcm

import (
	"encoding/binary"
	"errors"

	"github.com/pMag11-alt/handshake/internal/aes"
)

const (
	NonceSize = 12
	TagSize   = 16
)

var ErrOpen = errors.New("gcm: message authentication failed")

// element is a GF(2^128) value in GCM's bit order: the most significant bit
// of hi is the coefficient of x^0.
type element struct{ hi, lo uint64 }

// AEAD is an AES-GCM instance for one key.
type AEAD struct {
	block *aes.Block
	table [16]element
}

// reduction[i] is the reduction term for the four bits shifted out when
// multiplying by x^4.
var reduction = [16]uint64{
	0x0000, 0x1c20, 0x3840, 0x2460, 0x7080, 0x6ca0, 0x48c0, 0x54e0,
	0xe100, 0xfd20, 0xd940, 0xc560, 0x9180, 0x8da0, 0xa9c0, 0xb5e0,
}

func reverse4(i int) int {
	return (i&1)<<3 | (i&2)<<1 | (i&4)>>1 | (i&8)>>3
}

// double multiplies by x, reducing by x^128 + x^7 + x^2 + x + 1.
func double(e element) element {
	carry := e.lo & 1
	out := element{hi: e.hi >> 1, lo: e.lo>>1 | e.hi<<63}
	if carry != 0 {
		out.hi ^= 0xe100000000000000
	}
	return out
}

// New returns AES-GCM for a 16- or 32-byte key.
func New(key []byte) (*AEAD, error) {
	block, err := aes.New(key)
	if err != nil {
		return nil, err
	}
	g := &AEAD{block: block}
	var h [16]byte
	block.Encrypt(h[:], h[:])
	x := element{binary.BigEndian.Uint64(h[:8]), binary.BigEndian.Uint64(h[8:])}
	// Table indices are 4-bit chunks read in GCM's reflected bit order, so
	// the multiple k*H lives at index reverse4(k).
	g.table[reverse4(1)] = x
	for k := 2; k < 16; k += 2 {
		g.table[reverse4(k)] = double(g.table[reverse4(k/2)])
		t := g.table[reverse4(k)]
		g.table[reverse4(k+1)] = element{t.hi ^ x.hi, t.lo ^ x.lo}
	}
	return g, nil
}

func (g *AEAD) NonceSize() int { return NonceSize }
func (g *AEAD) Overhead() int  { return TagSize }

// mul sets y = y * H.
func (g *AEAD) mul(y *element) {
	var z element
	for _, word := range [2]uint64{y.lo, y.hi} {
		for j := 0; j < 64; j += 4 {
			// z = z * x^4, folding the bits that fall off back in.
			msw := z.lo & 0xf
			z.lo = z.lo>>4 | z.hi<<60
			z.hi = z.hi>>4 ^ reduction[msw]<<48
			t := g.table[word&0xf]
			z.hi ^= t.hi
			z.lo ^= t.lo
			word >>= 4
		}
	}
	*y = z
}

func (g *AEAD) ghashUpdate(y *element, data []byte) {
	for len(data) > 0 {
		var block [16]byte
		n := copy(block[:], data)
		data = data[n:]
		y.hi ^= binary.BigEndian.Uint64(block[:8])
		y.lo ^= binary.BigEndian.Uint64(block[8:])
		g.mul(y)
	}
}

func (g *AEAD) tag(counter0 *[16]byte, ciphertext, ad []byte) [16]byte {
	var y element
	g.ghashUpdate(&y, ad)
	g.ghashUpdate(&y, ciphertext)
	y.hi ^= uint64(len(ad)) * 8
	y.lo ^= uint64(len(ciphertext)) * 8
	g.mul(&y)
	var t [16]byte
	g.block.Encrypt(t[:], counter0[:])
	binary.BigEndian.PutUint64(t[:8], binary.BigEndian.Uint64(t[:8])^y.hi)
	binary.BigEndian.PutUint64(t[8:], binary.BigEndian.Uint64(t[8:])^y.lo)
	return t
}

// ctr XORs in the keystream starting at counter value 2.
func (g *AEAD) ctr(dst, src []byte, counter0 *[16]byte) {
	counter := *counter0
	var ks [16]byte
	for i := 0; i < len(src); i += 16 {
		c := binary.BigEndian.Uint32(counter[12:]) + 1
		binary.BigEndian.PutUint32(counter[12:], c)
		g.block.Encrypt(ks[:], counter[:])
		end := min(i+16, len(src))
		for j := i; j < end; j++ {
			dst[j] = src[j] ^ ks[j-i]
		}
	}
}

func j0(nonce []byte) [16]byte {
	var c [16]byte
	copy(c[:], nonce)
	c[15] = 1
	return c
}

// Seal appends the encryption of plaintext and its tag to dst.
func (g *AEAD) Seal(dst, nonce, plaintext, ad []byte) []byte {
	if len(nonce) != NonceSize {
		panic("gcm: nonce must be 12 bytes")
	}
	counter0 := j0(nonce)
	start := len(dst)
	out := append(dst, make([]byte, len(plaintext)+TagSize)...)
	ct := out[start : start+len(plaintext)]
	g.ctr(ct, plaintext, &counter0)
	t := g.tag(&counter0, ct, ad)
	copy(out[start+len(plaintext):], t[:])
	return out
}

// Open authenticates and decrypts ciphertext||tag, appending to dst.
func (g *AEAD) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(nonce) != NonceSize || len(ciphertext) < TagSize {
		return nil, ErrOpen
	}
	counter0 := j0(nonce)
	body := ciphertext[:len(ciphertext)-TagSize]
	t := g.tag(&counter0, body, ad)
	var diff byte
	for i, b := range ciphertext[len(body):] {
		diff |= b ^ t[i]
	}
	if diff != 0 {
		return nil, ErrOpen
	}
	start := len(dst)
	out := append(dst, make([]byte, len(body))...)
	g.ctr(out[start:], body, &counter0)
	return out, nil
}
