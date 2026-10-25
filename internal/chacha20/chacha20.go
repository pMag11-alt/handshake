// Package chacha20 implements the ChaCha20 stream cipher as specified for
// IETF protocols (RFC 8439): 256-bit key, 96-bit nonce, 32-bit counter.
package chacha20

import (
	"encoding/binary"
	"math/bits"
)

const (
	KeySize   = 32
	NonceSize = 12
)

func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d = bits.RotateLeft32(d^a, 16)
	c += d
	b = bits.RotateLeft32(b^c, 12)
	a += b
	d = bits.RotateLeft32(d^a, 8)
	c += d
	b = bits.RotateLeft32(b^c, 7)
	return a, b, c, d
}

// Block computes one 64-byte keystream block.
func Block(out *[64]byte, key *[32]byte, counter uint32, nonce *[12]byte) {
	var s [16]uint32
	s[0], s[1], s[2], s[3] = 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 // "expand 32-byte k"
	for i := 0; i < 8; i++ {
		s[4+i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	s[12] = counter
	s[13] = binary.LittleEndian.Uint32(nonce[0:])
	s[14] = binary.LittleEndian.Uint32(nonce[4:])
	s[15] = binary.LittleEndian.Uint32(nonce[8:])
	x := s
	for i := 0; i < 10; i++ {
		// Column rounds, then diagonal rounds.
		x[0], x[4], x[8], x[12] = quarterRound(x[0], x[4], x[8], x[12])
		x[1], x[5], x[9], x[13] = quarterRound(x[1], x[5], x[9], x[13])
		x[2], x[6], x[10], x[14] = quarterRound(x[2], x[6], x[10], x[14])
		x[3], x[7], x[11], x[15] = quarterRound(x[3], x[7], x[11], x[15])
		x[0], x[5], x[10], x[15] = quarterRound(x[0], x[5], x[10], x[15])
		x[1], x[6], x[11], x[12] = quarterRound(x[1], x[6], x[11], x[12])
		x[2], x[7], x[8], x[13] = quarterRound(x[2], x[7], x[8], x[13])
		x[3], x[4], x[9], x[14] = quarterRound(x[3], x[4], x[9], x[14])
	}
	for i := range x {
		binary.LittleEndian.PutUint32(out[i*4:], x[i]+s[i])
	}
}

// XORKeyStream encrypts or decrypts src into dst starting at block counter.
func XORKeyStream(dst, src []byte, key *[32]byte, nonce *[12]byte, counter uint32) {
	var ks [64]byte
	for i := 0; i < len(src); i += 64 {
		Block(&ks, key, counter, nonce)
		counter++
		end := min(i+64, len(src))
		for j := i; j < end; j++ {
			dst[j] = src[j] ^ ks[j-i]
		}
	}
}
