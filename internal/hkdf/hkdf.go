// Package hkdf implements HKDF (RFC 5869), the key derivation function at
// the heart of the TLS 1.3 key schedule.
package hkdf

import (
	"hash"

	"github.com/pMag11-alt/handshake/internal/hmac"
)

// Extract returns a pseudorandom key from input keying material and a salt.
// An empty salt means a string of hash-length zeros.
func Extract(h func() hash.Hash, secret, salt []byte) []byte {
	if len(salt) == 0 {
		salt = make([]byte, h().Size())
	}
	return hmac.Sum(h, salt, secret)
}

// Expand stretches a pseudorandom key to length bytes bound to info.
func Expand(h func() hash.Hash, prk, info []byte, length int) []byte {
	m := hmac.New(h, prk)
	out := make([]byte, 0, length)
	var prev []byte
	for counter := byte(1); len(out) < length; counter++ {
		m.Reset()
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{counter})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:length]
}
