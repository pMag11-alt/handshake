// Package chacha20poly1305 implements the ChaCha20-Poly1305 AEAD (RFC 8439).
package chacha20poly1305

import (
	"encoding/binary"
	"errors"

	"github.com/pMag11-alt/handshake/internal/chacha20"
	"github.com/pMag11-alt/handshake/internal/poly1305"
)

const (
	KeySize   = 32
	NonceSize = 12
	TagSize   = 16
)

var ErrOpen = errors.New("chacha20poly1305: message authentication failed")

type AEAD struct{ key [32]byte }

func New(key []byte) (*AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("chacha20poly1305: key must be 32 bytes")
	}
	a := &AEAD{}
	copy(a.key[:], key)
	return a, nil
}

func (a *AEAD) NonceSize() int { return NonceSize }
func (a *AEAD) Overhead() int  { return TagSize }

func (a *AEAD) tag(nonce *[12]byte, ciphertext, ad []byte) [16]byte {
	// The Poly1305 key is the first half of keystream block 0.
	var block [64]byte
	chacha20.Block(&block, &a.key, 0, nonce)
	var polyKey [32]byte
	copy(polyKey[:], block[:32])
	m := poly1305.New(&polyKey)
	var zeros [16]byte
	m.Write(ad)
	m.Write(zeros[:(16-len(ad)%16)%16])
	m.Write(ciphertext)
	m.Write(zeros[:(16-len(ciphertext)%16)%16])
	var lengths [16]byte
	binary.LittleEndian.PutUint64(lengths[0:], uint64(len(ad)))
	binary.LittleEndian.PutUint64(lengths[8:], uint64(len(ciphertext)))
	m.Write(lengths[:])
	return m.Sum()
}

func (a *AEAD) Seal(dst, nonce, plaintext, ad []byte) []byte {
	if len(nonce) != NonceSize {
		panic("chacha20poly1305: nonce must be 12 bytes")
	}
	n := (*[12]byte)(nonce)
	start := len(dst)
	out := append(dst, make([]byte, len(plaintext)+TagSize)...)
	ct := out[start : start+len(plaintext)]
	chacha20.XORKeyStream(ct, plaintext, &a.key, n, 1)
	t := a.tag(n, ct, ad)
	copy(out[start+len(plaintext):], t[:])
	return out
}

func (a *AEAD) Open(dst, nonce, ciphertext, ad []byte) ([]byte, error) {
	if len(nonce) != NonceSize || len(ciphertext) < TagSize {
		return nil, ErrOpen
	}
	n := (*[12]byte)(nonce)
	body := ciphertext[:len(ciphertext)-TagSize]
	t := a.tag(n, body, ad)
	var diff byte
	for i, b := range ciphertext[len(body):] {
		diff |= b ^ t[i]
	}
	if diff != 0 {
		return nil, ErrOpen
	}
	start := len(dst)
	out := append(dst, make([]byte, len(body))...)
	chacha20.XORKeyStream(out[start:], body, &a.key, n, 1)
	return out, nil
}
