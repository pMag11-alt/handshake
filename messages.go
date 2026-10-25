package handshake

import (
	"bytes"
	"errors"

	"github.com/pMag11-alt/handshake/internal/sha2"
)

// ---- wire encoding helpers ----------------------------------------------------------

type builder struct{ b []byte }

func (w *builder) u8(v uint8)     { w.b = append(w.b, v) }
func (w *builder) u16(v uint16)   { w.b = append(w.b, byte(v>>8), byte(v)) }
func (w *builder) u24(v int)      { w.b = append(w.b, byte(v>>16), byte(v>>8), byte(v)) }
func (w *builder) u32(v uint32)   { w.b = append(w.b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v)) }
func (w *builder) bytes(p []byte) { w.b = append(w.b, p...) }

// vec writes a length-prefixed vector; size is the prefix width in bytes.
func (w *builder) vec(size int, f func(*builder)) {
	start := len(w.b)
	w.b = append(w.b, make([]byte, size)...)
	f(w)
	n := len(w.b) - start - size
	for i := 0; i < size; i++ {
		w.b[start+i] = byte(n >> (8 * (size - 1 - i)))
	}
}

func (w *builder) vecBytes(size int, p []byte) { w.vec(size, func(w *builder) { w.bytes(p) }) }

// errDecode is raised by reader methods on truncated input and recovered
// by the message parsers.
var errDecode = errors.New("decode error")

type reader struct{ b []byte }

func (r *reader) take(n int) []byte {
	if n < 0 || len(r.b) < n {
		panic(errDecode)
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() uint8   { return r.take(1)[0] }
func (r *reader) u16() uint16 { b := r.take(2); return uint16(b[0])<<8 | uint16(b[1]) }
func (r *reader) u24() int    { b := r.take(3); return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }
func (r *reader) u32() uint32 {
	b := r.take(4)
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func (r *reader) vec(size int) []byte {
	n := 0
	for _, c := range r.take(size) {
		n = n<<8 | int(c)
	}
	return r.take(n)
}

func (r *reader) sub(size int) *reader { return &reader{r.vec(size)} }
func (r *reader) empty() bool          { return len(r.b) == 0 }

func (r *reader) done() {
	if len(r.b) != 0 {
		panic(errDecode)
	}
}

// decode runs f, turning a truncation panic into a decode_error alert.
func decode(what string, f func()) (err error) {
	defer func() {
		if p := recover(); p != nil {
			if p == errDecode {
				err = fail(alertDecodeError, "malformed %s", what)
				return
			}
			if e, ok := p.(*AlertError); ok {
				err = e
				return
			}
			panic(p)
		}
	}()
	f()
	return nil
}

// handshakeMessage wraps a body with its type and 24-bit length.
func handshakeMessage(typ uint8, body func(*builder)) []byte {
	w := &builder{}
	w.u8(typ)
	w.vec(3, body)
	return w.b
}

// ---- ClientHello --------------------------------------------------------------------

type keyShare struct {
	group CurveID
	data  []byte
}

type clientHello struct {
	random            []byte
	sessionID         []byte
	cipherSuites      []CipherSuite
	serverName        string
	supportedGroups   []CurveID
	signatureSchemes  []SignatureScheme
	supportedVersions []uint16
	keyShares         []keyShare
	cookie            []byte
	alpn              []string
	pskModes          []uint8
	// keyShareSeen distinguishes an empty key_share list from a missing one.
	keyShareSeen bool
}

func (m *clientHello) marshal() []byte {
	return handshakeMessage(typeClientHello, func(w *builder) {
		w.u16(versionTLS12) // legacy_version
		w.bytes(m.random)
		w.vecBytes(1, m.sessionID)
		w.vec(2, func(w *builder) {
			for _, s := range m.cipherSuites {
				w.u16(uint16(s))
			}
		})
		w.vecBytes(1, []byte{0}) // legacy compression: null only
		w.vec(2, func(w *builder) {
			if m.serverName != "" {
				w.u16(extServerName)
				w.vec(2, func(w *builder) {
					w.vec(2, func(w *builder) {
						w.u8(0) // host_name
						w.vecBytes(2, []byte(m.serverName))
					})
				})
			}
			w.u16(extSupportedGroups)
			w.vec(2, func(w *builder) {
				w.vec(2, func(w *builder) {
					for _, g := range m.supportedGroups {
						w.u16(uint16(g))
					}
				})
			})
			w.u16(extSignatureAlgorithms)
			w.vec(2, func(w *builder) {
				w.vec(2, func(w *builder) {
					for _, s := range m.signatureSchemes {
						w.u16(uint16(s))
					}
				})
			})
			if len(m.alpn) > 0 {
				w.u16(extALPN)
				w.vec(2, func(w *builder) {
					w.vec(2, func(w *builder) {
						for _, p := range m.alpn {
							w.vecBytes(1, []byte(p))
						}
					})
				})
			}
			w.u16(extSupportedVersions)
			w.vec(2, func(w *builder) {
				w.vec(1, func(w *builder) {
					for _, v := range m.supportedVersions {
						w.u16(v)
					}
				})
			})
			if len(m.cookie) > 0 {
				w.u16(extCookie)
				w.vec(2, func(w *builder) { w.vecBytes(2, m.cookie) })
			}
			w.u16(extPSKModes)
			w.vec(2, func(w *builder) { w.vecBytes(1, m.pskModes) })
			w.u16(extKeyShare)
			w.vec(2, func(w *builder) {
				w.vec(2, func(w *builder) {
					for _, ks := range m.keyShares {
						w.u16(uint16(ks.group))
						w.vecBytes(2, ks.data)
					}
				})
			})
		})
	})
}

func parseClientHello(body []byte) (*clientHello, error) {
	m := &clientHello{}
	err := decode("ClientHello", func() {
		r := &reader{body}
		r.u16() // legacy_version: real negotiation happens in supported_versions
		m.random = r.take(32)
		m.sessionID = r.vec(1)
		if len(m.sessionID) > 32 {
			panic(errDecode)
		}
		suites := r.sub(2)
		for !suites.empty() {
			m.cipherSuites = append(m.cipherSuites, CipherSuite(suites.u16()))
		}
		compression := r.vec(1)
		if !bytes.Equal(compression, []byte{0}) {
			panic(fail(alertIllegalParameter, "TLS 1.3 requires null compression"))
		}
		if r.empty() {
			return // a pre-TLS 1.2 hello with no extensions
		}
		exts := r.sub(2)
		r.done()
		seen := map[uint16]bool{}
		for !exts.empty() {
			typ := exts.u16()
			data := exts.sub(2)
			if seen[typ] {
				panic(fail(alertIllegalParameter, "duplicate extension %d", typ))
			}
			seen[typ] = true
			switch typ {
			case extServerName:
				list := data.sub(2)
				for !list.empty() {
					nameType := list.u8()
					name := list.vec(2)
					if nameType == 0 {
						m.serverName = string(name)
					}
				}
			case extSupportedGroups:
				list := data.sub(2)
				for !list.empty() {
					m.supportedGroups = append(m.supportedGroups, CurveID(list.u16()))
				}
			case extSignatureAlgorithms:
				list := data.sub(2)
				for !list.empty() {
					m.signatureSchemes = append(m.signatureSchemes, SignatureScheme(list.u16()))
				}
			case extALPN:
				list := data.sub(2)
				for !list.empty() {
					m.alpn = append(m.alpn, string(list.vec(1)))
				}
			case extSupportedVersions:
				list := data.sub(1)
				for !list.empty() {
					m.supportedVersions = append(m.supportedVersions, list.u16())
				}
			case extCookie:
				m.cookie = data.vec(2)
			case extPSKModes:
				m.pskModes = data.vec(1)
			case extKeyShare:
				m.keyShareSeen = true
				list := data.sub(2)
				for !list.empty() {
					g := CurveID(list.u16())
					m.keyShares = append(m.keyShares, keyShare{g, list.vec(2)})
				}
			default:
				continue // unknown extensions are ignored
			}
			data.done()
		}
	})
	return m, err
}

// ---- ServerHello and HelloRetryRequest --------------------------------------------

// hrrRandom marks a ServerHello as a HelloRetryRequest (RFC 8446 4.1.3).
var hrrRandom = sha2.Sum256([]byte("HelloRetryRequest"))

type serverHello struct {
	random           []byte
	sessionID        []byte
	cipherSuite      CipherSuite
	supportedVersion uint16
	keyShare         keyShare // in a ServerHello
	selectedGroup    CurveID  // in a HelloRetryRequest
	cookie           []byte
}

func (m *serverHello) isHelloRetry() bool { return bytes.Equal(m.random, hrrRandom) }

func (m *serverHello) marshal() []byte {
	return handshakeMessage(typeServerHello, func(w *builder) {
		w.u16(versionTLS12)
		w.bytes(m.random)
		w.vecBytes(1, m.sessionID)
		w.u16(uint16(m.cipherSuite))
		w.u8(0)
		w.vec(2, func(w *builder) {
			w.u16(extSupportedVersions)
			w.vec(2, func(w *builder) { w.u16(m.supportedVersion) })
			w.u16(extKeyShare)
			w.vec(2, func(w *builder) {
				if m.isHelloRetry() {
					w.u16(uint16(m.selectedGroup))
				} else {
					w.u16(uint16(m.keyShare.group))
					w.vecBytes(2, m.keyShare.data)
				}
			})
			if len(m.cookie) > 0 {
				w.u16(extCookie)
				w.vec(2, func(w *builder) { w.vecBytes(2, m.cookie) })
			}
		})
	})
}

func parseServerHello(body []byte) (*serverHello, error) {
	m := &serverHello{}
	err := decode("ServerHello", func() {
		r := &reader{body}
		r.u16()
		m.random = r.take(32)
		m.sessionID = r.vec(1)
		m.cipherSuite = CipherSuite(r.u16())
		if r.u8() != 0 {
			panic(fail(alertIllegalParameter, "server chose compression"))
		}
		if r.empty() {
			return // TLS 1.2 or older: no supported_versions
		}
		exts := r.sub(2)
		r.done()
		hrr := m.isHelloRetry()
		seen := map[uint16]bool{}
		for !exts.empty() {
			typ := exts.u16()
			data := exts.sub(2)
			if seen[typ] {
				panic(fail(alertIllegalParameter, "duplicate extension %d", typ))
			}
			seen[typ] = true
			switch typ {
			case extSupportedVersions:
				m.supportedVersion = data.u16()
			case extKeyShare:
				if hrr {
					m.selectedGroup = CurveID(data.u16())
				} else {
					m.keyShare.group = CurveID(data.u16())
					m.keyShare.data = data.vec(2)
				}
			case extCookie:
				m.cookie = data.vec(2)
			default:
				// RFC 8446 4.1.3: the client must reject extensions it
				// did not offer.
				panic(fail(alertUnsupportedExtension, "unexpected extension %d in ServerHello", typ))
			}
			data.done()
		}
	})
	return m, err
}

// ---- encrypted handshake messages ---------------------------------------------------

type encryptedExtensions struct {
	alpn string
}

func (m *encryptedExtensions) marshal() []byte {
	return handshakeMessage(typeEncryptedExtensions, func(w *builder) {
		w.vec(2, func(w *builder) {
			if m.alpn != "" {
				w.u16(extALPN)
				w.vec(2, func(w *builder) {
					w.vec(2, func(w *builder) { w.vecBytes(1, []byte(m.alpn)) })
				})
			}
		})
	})
}

func parseEncryptedExtensions(body []byte) (*encryptedExtensions, error) {
	m := &encryptedExtensions{}
	err := decode("EncryptedExtensions", func() {
		r := &reader{body}
		exts := r.sub(2)
		r.done()
		for !exts.empty() {
			typ := exts.u16()
			data := exts.sub(2)
			if typ == extALPN {
				list := data.sub(2)
				m.alpn = string(list.vec(1))
				list.done()
			}
		}
	})
	return m, err
}

type certificateMsg struct {
	context []byte
	chain   [][]byte
}

func (m *certificateMsg) marshal() []byte {
	return handshakeMessage(typeCertificate, func(w *builder) {
		w.vecBytes(1, m.context)
		w.vec(3, func(w *builder) {
			for _, cert := range m.chain {
				w.vecBytes(3, cert)
				w.u16(0) // no per-certificate extensions
			}
		})
	})
}

func parseCertificate(body []byte) (*certificateMsg, error) {
	m := &certificateMsg{}
	err := decode("Certificate", func() {
		r := &reader{body}
		m.context = r.vec(1)
		list := r.sub(3)
		r.done()
		for !list.empty() {
			m.chain = append(m.chain, list.vec(3))
			list.vec(2) // extensions (OCSP, SCTs) are not used
		}
	})
	return m, err
}

type certificateRequestMsg struct {
	context []byte
}

func parseCertificateRequest(body []byte) (*certificateRequestMsg, error) {
	m := &certificateRequestMsg{}
	err := decode("CertificateRequest", func() {
		r := &reader{body}
		m.context = r.vec(1)
		r.vec(2)
		r.done()
	})
	return m, err
}

type certificateVerifyMsg struct {
	scheme    SignatureScheme
	signature []byte
}

func (m *certificateVerifyMsg) marshal() []byte {
	return handshakeMessage(typeCertificateVerify, func(w *builder) {
		w.u16(uint16(m.scheme))
		w.vecBytes(2, m.signature)
	})
}

func parseCertificateVerify(body []byte) (*certificateVerifyMsg, error) {
	m := &certificateVerifyMsg{}
	err := decode("CertificateVerify", func() {
		r := &reader{body}
		m.scheme = SignatureScheme(r.u16())
		m.signature = r.vec(2)
		r.done()
	})
	return m, err
}

func marshalFinished(verifyData []byte) []byte {
	return handshakeMessage(typeFinished, func(w *builder) { w.bytes(verifyData) })
}

type newSessionTicketMsg struct {
	lifetime uint32
	ageAdd   uint32
	nonce    []byte
	ticket   []byte
}

func parseNewSessionTicket(body []byte) (*newSessionTicketMsg, error) {
	m := &newSessionTicketMsg{}
	err := decode("NewSessionTicket", func() {
		r := &reader{body}
		m.lifetime = r.u32()
		m.ageAdd = r.u32()
		m.nonce = r.vec(1)
		m.ticket = r.vec(2)
		r.vec(2)
		r.done()
	})
	return m, err
}

func marshalKeyUpdate(requestUpdate bool) []byte {
	return handshakeMessage(typeKeyUpdate, func(w *builder) {
		if requestUpdate {
			w.u8(1)
		} else {
			w.u8(0)
		}
	})
}
