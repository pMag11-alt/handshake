package poly1305

import (
	"math/big"
	"math/rand"
	"testing"
)

// reference computes Poly1305 directly with big integers.
func reference(msg []byte, key *[32]byte) [16]byte {
	le := func(b []byte) *big.Int {
		r := make([]byte, len(b))
		for i := range b {
			r[len(b)-1-i] = b[i]
		}
		return new(big.Int).SetBytes(r)
	}
	rb := make([]byte, 16)
	copy(rb, key[:16])
	rb[3] &= 15
	rb[7] &= 15
	rb[11] &= 15
	rb[15] &= 15
	rb[4] &= 252
	rb[8] &= 252
	rb[12] &= 252
	r := le(rb)
	s := le(key[16:])
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 130), big.NewInt(5))
	acc := new(big.Int)
	for i := 0; i < len(msg); i += 16 {
		end := min(i+16, len(msg))
		block := append(append([]byte(nil), msg[i:end]...), 1)
		acc.Add(acc, le(block))
		acc.Mul(acc, r)
		acc.Mod(acc, p)
	}
	acc.Add(acc, s)
	out := acc.Bytes()
	var tag [16]byte
	for i := 0; i < 16 && i < len(out); i++ {
		tag[i] = out[len(out)-1-i]
	}
	return tag
}

// Random keys and messages, with keys biased towards all-ones limbs so the
// accumulator's carries are exercised.
func TestAgainstBigIntReference(t *testing.T) {
	r := rand.New(rand.NewSource(5))
	for i := 0; i < 3000; i++ {
		var key [32]byte
		r.Read(key[:])
		if i%3 == 0 {
			for j := range key {
				key[j] = 0xff
			}
		}
		msg := make([]byte, r.Intn(100))
		r.Read(msg)
		if i%5 == 0 {
			for j := range msg {
				msg[j] = 0xff
			}
		}
		m := New(&key)
		for rest := msg; len(rest) > 0; {
			k := r.Intn(len(rest)) + 1
			m.Write(rest[:k])
			rest = rest[k:]
		}
		if got, want := m.Sum(), reference(msg, &key); got != want {
			t.Fatalf("case %d (len %d): got %x want %x", i, len(msg), got, want)
		}
	}
}
