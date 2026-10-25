// Package aes implements the AES block cipher (FIPS 197), encryption only:
// GCM and the other modes TLS uses never run the cipher backwards.
//
// Rounds use the classic T-table formulation, combining SubBytes, ShiftRows
// and MixColumns into four 256-entry lookups per column. Table lookups are
// indexed by secret data, so this implementation is not constant-time; it
// is written for clarity, not to resist cache-timing attacks.
package aes

import (
	"encoding/binary"
	"errors"
)

const BlockSize = 16

var (
	sbox               [256]byte
	te0, te1, te2, te3 [256]uint32
	rcon               [15]uint32
)

// mul multiplies in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1.
func mul(a, b byte) byte {
	var p byte
	for b != 0 {
		if b&1 != 0 {
			p ^= a
		}
		hi := a & 0x80
		a <<= 1
		if hi != 0 {
			a ^= 0x1b
		}
		b >>= 1
	}
	return p
}

func rotl8(x byte, n uint) byte { return x<<n | x>>(8-n) }

func init() {
	// S-box: multiplicative inverse (x^254) followed by the affine map.
	for i := 0; i < 256; i++ {
		x := byte(i)
		inv := byte(0)
		if x != 0 {
			inv = 1
			for k := 0; k < 254; k++ {
				inv = mul(inv, x)
			}
		}
		sbox[i] = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^ rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63
	}
	for i := 0; i < 256; i++ {
		s := sbox[i]
		w := uint32(mul(s, 2))<<24 | uint32(s)<<16 | uint32(s)<<8 | uint32(mul(s, 3))
		te0[i] = w
		te1[i] = w>>8 | w<<24
		te2[i] = w>>16 | w<<16
		te3[i] = w>>24 | w<<8
	}
	r := byte(1)
	for i := range rcon {
		rcon[i] = uint32(r) << 24
		r = mul(r, 2)
	}
}

func subWord(w uint32) uint32 {
	return uint32(sbox[w>>24])<<24 | uint32(sbox[w>>16&0xff])<<16 | uint32(sbox[w>>8&0xff])<<8 | uint32(sbox[w&0xff])
}

// Block is an expanded AES key.
type Block struct {
	rk     []uint32
	rounds int
}

// New expands a 16-, 24- or 32-byte key.
func New(key []byte) (*Block, error) {
	nk := len(key) / 4
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("aes: key must be 16, 24 or 32 bytes")
	}
	rounds := nk + 6
	rk := make([]uint32, 4*(rounds+1))
	for i := 0; i < nk; i++ {
		rk[i] = binary.BigEndian.Uint32(key[4*i:])
	}
	for i := nk; i < len(rk); i++ {
		t := rk[i-1]
		if i%nk == 0 {
			t = subWord(t<<8|t>>24) ^ rcon[i/nk-1]
		} else if nk > 6 && i%nk == 4 {
			t = subWord(t)
		}
		rk[i] = rk[i-nk] ^ t
	}
	return &Block{rk: rk, rounds: rounds}, nil
}

func (b *Block) BlockSize() int { return BlockSize }

// Encrypt encrypts one 16-byte block from src into dst (they may overlap).
func (b *Block) Encrypt(dst, src []byte) {
	rk := b.rk
	s0 := binary.BigEndian.Uint32(src[0:]) ^ rk[0]
	s1 := binary.BigEndian.Uint32(src[4:]) ^ rk[1]
	s2 := binary.BigEndian.Uint32(src[8:]) ^ rk[2]
	s3 := binary.BigEndian.Uint32(src[12:]) ^ rk[3]
	k := 4
	for r := 1; r < b.rounds; r++ {
		t0 := te0[s0>>24] ^ te1[s1>>16&0xff] ^ te2[s2>>8&0xff] ^ te3[s3&0xff] ^ rk[k]
		t1 := te0[s1>>24] ^ te1[s2>>16&0xff] ^ te2[s3>>8&0xff] ^ te3[s0&0xff] ^ rk[k+1]
		t2 := te0[s2>>24] ^ te1[s3>>16&0xff] ^ te2[s0>>8&0xff] ^ te3[s1&0xff] ^ rk[k+2]
		t3 := te0[s3>>24] ^ te1[s0>>16&0xff] ^ te2[s1>>8&0xff] ^ te3[s2&0xff] ^ rk[k+3]
		s0, s1, s2, s3 = t0, t1, t2, t3
		k += 4
	}
	// The last round has no MixColumns.
	last := func(a, b, c, d uint32) uint32 {
		return uint32(sbox[a>>24])<<24 | uint32(sbox[b>>16&0xff])<<16 | uint32(sbox[c>>8&0xff])<<8 | uint32(sbox[d&0xff])
	}
	binary.BigEndian.PutUint32(dst[0:], last(s0, s1, s2, s3)^rk[k])
	binary.BigEndian.PutUint32(dst[4:], last(s1, s2, s3, s0)^rk[k+1])
	binary.BigEndian.PutUint32(dst[8:], last(s2, s3, s0, s1)^rk[k+2])
	binary.BigEndian.PutUint32(dst[12:], last(s3, s0, s1, s2)^rk[k+3])
}
