package handshake

import (
	"hash"

	"github.com/pMag11-alt/handshake/internal/chacha20poly1305"
	"github.com/pMag11-alt/handshake/internal/gcm"
	"github.com/pMag11-alt/handshake/internal/hkdf"
	"github.com/pMag11-alt/handshake/internal/hmac"
	"github.com/pMag11-alt/handshake/internal/sha2"
)

// aead is satisfied by both AES-GCM and ChaCha20-Poly1305.
type aead interface {
	NonceSize() int
	Overhead() int
	Seal(dst, nonce, plaintext, ad []byte) []byte
	Open(dst, nonce, ciphertext, ad []byte) ([]byte, error)
}

type suite struct {
	id      CipherSuite
	keyLen  int
	newHash func() hash.Hash
	newAEAD func(key []byte) (aead, error)
}

var suites = map[CipherSuite]*suite{
	TLS_AES_128_GCM_SHA256: {TLS_AES_128_GCM_SHA256, 16, sha2.New256,
		func(k []byte) (aead, error) { return gcm.New(k) }},
	TLS_AES_256_GCM_SHA384: {TLS_AES_256_GCM_SHA384, 32, sha2.New384,
		func(k []byte) (aead, error) { return gcm.New(k) }},
	TLS_CHACHA20_POLY1305_SHA256: {TLS_CHACHA20_POLY1305_SHA256, 32, sha2.New256,
		func(k []byte) (aead, error) { return chacha20poly1305.New(k) }},
}

func (s *suite) hashSize() int { return s.newHash().Size() }

// expandLabel is HKDF-Expand-Label from RFC 8446 section 7.1.
func (s *suite) expandLabel(secret []byte, label string, context []byte, length int) []byte {
	w := &builder{}
	w.u16(uint16(length))
	w.vecBytes(1, []byte("tls13 "+label))
	w.vecBytes(1, context)
	return hkdf.Expand(s.newHash, secret, w.b, length)
}

// deriveSecret is Derive-Secret: the label bound to a transcript hash.
func (s *suite) deriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	var sum []byte
	if transcript == nil {
		sum = s.newHash().Sum(nil)
	} else {
		sum = transcript.Sum(nil)
	}
	return s.expandLabel(secret, label, sum, s.hashSize())
}

func (s *suite) extract(ikm, salt []byte) []byte {
	if ikm == nil {
		ikm = make([]byte, s.hashSize())
	}
	return hkdf.Extract(s.newHash, ikm, salt)
}

// trafficKeys derives the AEAD key and static IV for a traffic secret.
func (s *suite) trafficKeys(secret []byte) (key, iv []byte) {
	return s.expandLabel(secret, "key", nil, s.keyLen), s.expandLabel(secret, "iv", nil, 12)
}

// finished computes Finished.verify_data for a handshake traffic secret.
func (s *suite) finished(secret []byte, transcript hash.Hash) []byte {
	key := s.expandLabel(secret, "finished", nil, s.hashSize())
	return hmac.Sum(s.newHash, key, transcript.Sum(nil))
}

// nextTrafficSecret implements KeyUpdate (RFC 8446 section 7.2).
func (s *suite) nextTrafficSecret(secret []byte) []byte {
	return s.expandLabel(secret, "traffic upd", nil, s.hashSize())
}

// schedule tracks the secrets of one connection as the handshake advances.
type schedule struct {
	suite                  *suite
	handshakeSecret        []byte
	clientHandshakeTraffic []byte
	serverHandshakeTraffic []byte
	masterSecret           []byte
	clientAppTraffic       []byte
	serverAppTraffic       []byte
	exporterMaster         []byte
}

// handshake runs Early Secret -> Handshake Secret with the (EC)DHE output.
// There is no PSK, so the early secret's input is all zeros.
func (k *schedule) handshake(shared []byte, transcript hash.Hash) {
	s := k.suite
	early := s.extract(nil, nil)
	k.handshakeSecret = s.extract(shared, s.deriveSecret(early, "derived", nil))
	k.clientHandshakeTraffic = s.deriveSecret(k.handshakeSecret, "c hs traffic", transcript)
	k.serverHandshakeTraffic = s.deriveSecret(k.handshakeSecret, "s hs traffic", transcript)
}

// application derives the master secret and application traffic secrets
// from the transcript through the server's Finished.
func (k *schedule) application(transcript hash.Hash) {
	s := k.suite
	k.masterSecret = s.extract(nil, s.deriveSecret(k.handshakeSecret, "derived", nil))
	k.clientAppTraffic = s.deriveSecret(k.masterSecret, "c ap traffic", transcript)
	k.serverAppTraffic = s.deriveSecret(k.masterSecret, "s ap traffic", transcript)
	k.exporterMaster = s.deriveSecret(k.masterSecret, "exp master", transcript)
}
