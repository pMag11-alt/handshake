// Package poly1305 implements the Poly1305 one-time authenticator (RFC 8439)
// using five 26-bit limbs, so every product fits in 64 bits.
package poly1305

import "encoding/binary"

const TagSize = 16

// MAC accumulates a Poly1305 tag. A key must never be used twice.
type MAC struct {
	r, s [5]uint32 // s holds r*5 for the reduction shortcut
	pad  [4]uint32
	h    [5]uint32
	buf  [16]byte
	n    int
}

// New keys a MAC with a 32-byte one-time key (r || s).
func New(key *[32]byte) *MAC {
	m := &MAC{}
	// Clamp r as the RFC requires.
	m.r[0] = binary.LittleEndian.Uint32(key[0:]) & 0x3ffffff
	m.r[1] = binary.LittleEndian.Uint32(key[3:]) >> 2 & 0x3ffff03
	m.r[2] = binary.LittleEndian.Uint32(key[6:]) >> 4 & 0x3ffc0ff
	m.r[3] = binary.LittleEndian.Uint32(key[9:]) >> 6 & 0x3f03fff
	m.r[4] = binary.LittleEndian.Uint32(key[12:]) >> 8 & 0x00fffff
	for i := 1; i < 5; i++ {
		m.s[i] = m.r[i] * 5
	}
	for i := 0; i < 4; i++ {
		m.pad[i] = binary.LittleEndian.Uint32(key[16+i*4:])
	}
	return m
}

// block absorbs one 16-byte block; hibit is 1<<24 for full blocks and 0
// for the padded final block, which carries its own 0x01 byte.
func (m *MAC) block(b []byte, hibit uint32) {
	r0, r1, r2, r3, r4 := uint64(m.r[0]), uint64(m.r[1]), uint64(m.r[2]), uint64(m.r[3]), uint64(m.r[4])
	s1, s2, s3, s4 := uint64(m.s[1]), uint64(m.s[2]), uint64(m.s[3]), uint64(m.s[4])
	h0 := m.h[0] + binary.LittleEndian.Uint32(b[0:])&0x3ffffff
	h1 := m.h[1] + binary.LittleEndian.Uint32(b[3:])>>2&0x3ffffff
	h2 := m.h[2] + binary.LittleEndian.Uint32(b[6:])>>4&0x3ffffff
	h3 := m.h[3] + binary.LittleEndian.Uint32(b[9:])>>6&0x3ffffff
	h4 := m.h[4] + (binary.LittleEndian.Uint32(b[12:])>>8 | hibit)

	d0 := uint64(h0)*r0 + uint64(h1)*s4 + uint64(h2)*s3 + uint64(h3)*s2 + uint64(h4)*s1
	d1 := uint64(h0)*r1 + uint64(h1)*r0 + uint64(h2)*s4 + uint64(h3)*s3 + uint64(h4)*s2
	d2 := uint64(h0)*r2 + uint64(h1)*r1 + uint64(h2)*r0 + uint64(h3)*s4 + uint64(h4)*s3
	d3 := uint64(h0)*r3 + uint64(h1)*r2 + uint64(h2)*r1 + uint64(h3)*r0 + uint64(h4)*s4
	d4 := uint64(h0)*r4 + uint64(h1)*r3 + uint64(h2)*r2 + uint64(h3)*r1 + uint64(h4)*r0

	// Carry propagation; the carry out of the top limb wraps around times 5
	// because 2^130 = 5 (mod 2^130 - 5).
	c := d0 >> 26
	h0 = uint32(d0) & 0x3ffffff
	d1 += c
	c = d1 >> 26
	h1 = uint32(d1) & 0x3ffffff
	d2 += c
	c = d2 >> 26
	h2 = uint32(d2) & 0x3ffffff
	d3 += c
	c = d3 >> 26
	h3 = uint32(d3) & 0x3ffffff
	d4 += c
	c = d4 >> 26
	h4 = uint32(d4) & 0x3ffffff
	h0 += uint32(c) * 5
	h1 += h0 >> 26
	h0 &= 0x3ffffff
	m.h = [5]uint32{h0, h1, h2, h3, h4}
}

func (m *MAC) Write(p []byte) {
	if m.n > 0 {
		k := copy(m.buf[m.n:], p)
		m.n += k
		p = p[k:]
		if m.n < 16 {
			return
		}
		m.block(m.buf[:], 1<<24)
		m.n = 0
	}
	for len(p) >= 16 {
		m.block(p[:16], 1<<24)
		p = p[16:]
	}
	m.n = copy(m.buf[:], p)
}

// Sum returns the tag. The MAC must not be used afterwards.
func (m *MAC) Sum() [TagSize]byte {
	if m.n > 0 {
		m.buf[m.n] = 1
		for i := m.n + 1; i < 16; i++ {
			m.buf[i] = 0
		}
		m.block(m.buf[:], 0)
	}
	h0, h1, h2, h3, h4 := m.h[0], m.h[1], m.h[2], m.h[3], m.h[4]
	// Fully carry h.
	c := h1 >> 26
	h1 &= 0x3ffffff
	h2 += c
	c = h2 >> 26
	h2 &= 0x3ffffff
	h3 += c
	c = h3 >> 26
	h3 &= 0x3ffffff
	h4 += c
	c = h4 >> 26
	h4 &= 0x3ffffff
	h0 += c * 5
	c = h0 >> 26
	h0 &= 0x3ffffff
	h1 += c

	// Compute h - p and keep it if it didn't underflow, without branching.
	g0 := h0 + 5
	c = g0 >> 26
	g0 &= 0x3ffffff
	g1 := h1 + c
	c = g1 >> 26
	g1 &= 0x3ffffff
	g2 := h2 + c
	c = g2 >> 26
	g2 &= 0x3ffffff
	g3 := h3 + c
	c = g3 >> 26
	g3 &= 0x3ffffff
	g4 := h4 + c - 1<<26
	mask := (g4 >> 31) - 1 // all ones if h >= p
	g0 &= mask
	g1 &= mask
	g2 &= mask
	g3 &= mask
	g4 &= mask
	mask = ^mask
	h0 = h0&mask | g0
	h1 = h1&mask | g1
	h2 = h2&mask | g2
	h3 = h3&mask | g3
	h4 = h4&mask | g4

	// h = (h + pad) mod 2^128, repacked into four 32-bit words.
	w0 := uint64(h0 | h1<<26)
	w1 := uint64(h1>>6 | h2<<20)
	w2 := uint64(h2>>12 | h3<<14)
	w3 := uint64(h3>>18 | h4<<8)
	var tag [TagSize]byte
	f := (w0 & 0xffffffff) + uint64(m.pad[0])
	binary.LittleEndian.PutUint32(tag[0:], uint32(f))
	f = (w1 & 0xffffffff) + uint64(m.pad[1]) + f>>32
	binary.LittleEndian.PutUint32(tag[4:], uint32(f))
	f = (w2 & 0xffffffff) + uint64(m.pad[2]) + f>>32
	binary.LittleEndian.PutUint32(tag[8:], uint32(f))
	f = (w3 & 0xffffffff) + uint64(m.pad[3]) + f>>32
	binary.LittleEndian.PutUint32(tag[12:], uint32(f))
	return tag
}

// Sum computes the tag of msg in one call.
func Sum(msg []byte, key *[32]byte) [TagSize]byte {
	m := New(key)
	m.Write(msg)
	return m.Sum()
}
