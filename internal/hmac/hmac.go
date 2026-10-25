// Package hmac implements HMAC (RFC 2104) over any hash.Hash.
package hmac

import "hash"

type mac struct {
	inner, outer hash.Hash
	ipad, opad   []byte
}

// New returns an HMAC keyed with key, using the hash produced by h.
func New(h func() hash.Hash, key []byte) hash.Hash {
	m := &mac{inner: h(), outer: h()}
	bs := m.inner.BlockSize()
	if len(key) > bs {
		m.inner.Write(key)
		key = m.inner.Sum(nil)
		m.inner.Reset()
	}
	m.ipad = make([]byte, bs)
	m.opad = make([]byte, bs)
	copy(m.ipad, key)
	copy(m.opad, key)
	for i := range m.ipad {
		m.ipad[i] ^= 0x36
		m.opad[i] ^= 0x5c
	}
	m.inner.Write(m.ipad)
	return m
}

func (m *mac) Write(p []byte) (int, error) { return m.inner.Write(p) }
func (m *mac) Size() int                   { return m.inner.Size() }
func (m *mac) BlockSize() int              { return m.inner.BlockSize() }

func (m *mac) Reset() {
	m.inner.Reset()
	m.inner.Write(m.ipad)
}

func (m *mac) Sum(in []byte) []byte {
	inner := m.inner.Sum(nil)
	m.outer.Reset()
	m.outer.Write(m.opad)
	m.outer.Write(inner)
	return m.outer.Sum(in)
}

// Sum computes HMAC(key, data) in one call.
func Sum(h func() hash.Hash, key, data []byte) []byte {
	m := New(h, key)
	m.Write(data)
	return m.Sum(nil)
}

// Equal compares two MACs in constant time.
func Equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
