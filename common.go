// Package handshake is a TLS 1.3 (RFC 8446) client and server written from
// scratch: the record layer, the handshake state machines, the key schedule
// and every cryptographic primitive underneath them live in this module.
// From the standard library it uses only crypto/rand, for entropy, and
// math/big, for RSA and NIST-curve arithmetic.
//
//	conn, err := handshake.Dial("tcp", "example.com:443", nil)
//	if err != nil { ... }
//	defer conn.Close()
//	conn.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
package handshake

import (
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/pMag11-alt/handshake/internal/x509"
)

const (
	VersionTLS13 = 0x0304
	versionTLS12 = 0x0303
	versionTLS10 = 0x0301
)

// Record content types.
const (
	recordChangeCipherSpec uint8 = 20
	recordAlert            uint8 = 21
	recordHandshake        uint8 = 22
	recordApplicationData  uint8 = 23
)

// Handshake message types.
const (
	typeClientHello         uint8 = 1
	typeServerHello         uint8 = 2
	typeNewSessionTicket    uint8 = 4
	typeEncryptedExtensions uint8 = 8
	typeCertificate         uint8 = 11
	typeCertificateRequest  uint8 = 13
	typeCertificateVerify   uint8 = 15
	typeFinished            uint8 = 20
	typeKeyUpdate           uint8 = 24
	typeMessageHash         uint8 = 254
)

// Extension types.
const (
	extServerName          uint16 = 0
	extSupportedGroups     uint16 = 10
	extSignatureAlgorithms uint16 = 13
	extALPN                uint16 = 16
	extSupportedVersions   uint16 = 43
	extCookie              uint16 = 44
	extPSKModes            uint16 = 45
	extKeyShare            uint16 = 51
)

const (
	maxPlaintext  = 1 << 14
	maxCiphertext = maxPlaintext + 256
)

// CipherSuite is a TLS 1.3 cipher suite: an AEAD and a hash for HKDF.
type CipherSuite uint16

const (
	TLS_AES_128_GCM_SHA256       CipherSuite = 0x1301
	TLS_AES_256_GCM_SHA384       CipherSuite = 0x1302
	TLS_CHACHA20_POLY1305_SHA256 CipherSuite = 0x1303
)

func (s CipherSuite) String() string {
	switch s {
	case TLS_AES_128_GCM_SHA256:
		return "TLS_AES_128_GCM_SHA256"
	case TLS_AES_256_GCM_SHA384:
		return "TLS_AES_256_GCM_SHA384"
	case TLS_CHACHA20_POLY1305_SHA256:
		return "TLS_CHACHA20_POLY1305_SHA256"
	}
	return fmt.Sprintf("CipherSuite(0x%04x)", uint16(s))
}

// CurveID names a key-exchange group.
type CurveID uint16

const (
	X25519 CurveID = 0x001d
	P256   CurveID = 0x0017
	P384   CurveID = 0x0018
)

func (c CurveID) String() string {
	switch c {
	case X25519:
		return "X25519"
	case P256:
		return "P-256"
	case P384:
		return "P-384"
	}
	return fmt.Sprintf("CurveID(0x%04x)", uint16(c))
}

// SignatureScheme names a signature algorithm for CertificateVerify.
type SignatureScheme uint16

const (
	PKCS1WithSHA256        SignatureScheme = 0x0401
	PKCS1WithSHA384        SignatureScheme = 0x0501
	PKCS1WithSHA512        SignatureScheme = 0x0601
	ECDSAWithP256AndSHA256 SignatureScheme = 0x0403
	ECDSAWithP384AndSHA384 SignatureScheme = 0x0503
	PSSWithSHA256          SignatureScheme = 0x0804
	PSSWithSHA384          SignatureScheme = 0x0805
	PSSWithSHA512          SignatureScheme = 0x0806
)

func (s SignatureScheme) String() string {
	switch s {
	case PKCS1WithSHA256:
		return "rsa_pkcs1_sha256"
	case PKCS1WithSHA384:
		return "rsa_pkcs1_sha384"
	case PKCS1WithSHA512:
		return "rsa_pkcs1_sha512"
	case ECDSAWithP256AndSHA256:
		return "ecdsa_secp256r1_sha256"
	case ECDSAWithP384AndSHA384:
		return "ecdsa_secp384r1_sha384"
	case PSSWithSHA256:
		return "rsa_pss_rsae_sha256"
	case PSSWithSHA384:
		return "rsa_pss_rsae_sha384"
	case PSSWithSHA512:
		return "rsa_pss_rsae_sha512"
	}
	return fmt.Sprintf("SignatureScheme(0x%04x)", uint16(s))
}

var (
	defaultCipherSuites = []CipherSuite{TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384}
	defaultCurves       = []CurveID{X25519, P256, P384}
	// The PKCS #1 schemes are offered for certificate signatures only;
	// TLS 1.3 forbids them in CertificateVerify.
	defaultSignatureSchemes = []SignatureScheme{
		ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384,
		PSSWithSHA256, PSSWithSHA384, PSSWithSHA512,
		PKCS1WithSHA256, PKCS1WithSHA384, PKCS1WithSHA512,
	}
)

// Certificate is a chain (leaf first, DER) and the leaf's private key,
// which must be *rsa.PrivateKey or *ecc.PrivateKey from this module.
type Certificate struct {
	Chain      [][]byte
	PrivateKey any
}

// Config configures a client or a server. A nil *Config is valid for
// clients and uses safe defaults.
type Config struct {
	// ServerName is sent in SNI and checked against the certificate. Dial
	// fills it from the address when empty.
	ServerName string
	// RootCAs are the trust anchors. Nil means the system bundle.
	RootCAs *x509.Pool
	// InsecureSkipVerify disables certificate verification. For testing
	// against servers with throwaway certificates only.
	InsecureSkipVerify bool

	// Certificate is the server's certificate and key.
	Certificate *Certificate

	CipherSuites     []CipherSuite // in preference order
	CurvePreferences []CurveID     // in preference order; the first gets a key share
	NextProtos       []string      // ALPN, e.g. "h2", "http/1.1"

	// KeyLogWriter receives secrets in the NSS key log format, so Wireshark
	// can decrypt captures. Never use it in production.
	KeyLogWriter io.Writer
	// Trace, when set, is called with a line describing each handshake step.
	Trace func(string)

	Rand io.Reader
	Time func() time.Time
}

func (c *Config) rand() io.Reader {
	if c != nil && c.Rand != nil {
		return c.Rand
	}
	return rand.Reader
}

func (c *Config) now() time.Time {
	if c != nil && c.Time != nil {
		return c.Time()
	}
	return time.Now()
}

func (c *Config) cipherSuites() []CipherSuite {
	if c != nil && len(c.CipherSuites) > 0 {
		return c.CipherSuites
	}
	return defaultCipherSuites
}

func (c *Config) curves() []CurveID {
	if c != nil && len(c.CurvePreferences) > 0 {
		return c.CurvePreferences
	}
	return defaultCurves
}

// ConnectionState describes a completed handshake.
type ConnectionState struct {
	Version           uint16
	CipherSuite       CipherSuite
	Group             CurveID
	SignatureScheme   SignatureScheme
	ServerName        string
	NegotiatedProto   string
	HelloRetried      bool
	PeerCertificates  []*x509.Certificate
	VerifiedChain     []*x509.Certificate
	HandshakeDuration time.Duration
}

// ---- alerts ---------------------------------------------------------------------

type alert uint8

const (
	alertCloseNotify            alert = 0
	alertUnexpectedMessage      alert = 10
	alertBadRecordMAC           alert = 20
	alertRecordOverflow         alert = 22
	alertHandshakeFailure       alert = 40
	alertBadCertificate         alert = 42
	alertUnsupportedCertificate alert = 43
	alertCertificateExpired     alert = 45
	alertCertificateUnknown     alert = 46
	alertIllegalParameter       alert = 47
	alertUnknownCA              alert = 48
	alertDecodeError            alert = 50
	alertDecryptError           alert = 51
	alertProtocolVersion        alert = 70
	alertInternalError          alert = 80
	alertUserCanceled           alert = 90
	alertMissingExtension       alert = 109
	alertUnsupportedExtension   alert = 110
	alertUnrecognizedName       alert = 112
	alertNoApplicationProtocol  alert = 120
)

var alertNames = map[alert]string{
	alertCloseNotify:            "close_notify",
	alertUnexpectedMessage:      "unexpected_message",
	alertBadRecordMAC:           "bad_record_mac",
	alertRecordOverflow:         "record_overflow",
	alertHandshakeFailure:       "handshake_failure",
	alertBadCertificate:         "bad_certificate",
	alertUnsupportedCertificate: "unsupported_certificate",
	alertCertificateExpired:     "certificate_expired",
	alertCertificateUnknown:     "certificate_unknown",
	alertIllegalParameter:       "illegal_parameter",
	alertUnknownCA:              "unknown_ca",
	alertDecodeError:            "decode_error",
	alertDecryptError:           "decrypt_error",
	alertProtocolVersion:        "protocol_version",
	alertInternalError:          "internal_error",
	alertUserCanceled:           "user_canceled",
	alertMissingExtension:       "missing_extension",
	alertUnsupportedExtension:   "unsupported_extension",
	alertUnrecognizedName:       "unrecognized_name",
	alertNoApplicationProtocol:  "no_application_protocol",
}

func (a alert) String() string {
	if s, ok := alertNames[a]; ok {
		return s
	}
	return fmt.Sprintf("alert(%d)", uint8(a))
}

// AlertError reports a fatal alert, sent by us or received from the peer.
type AlertError struct {
	Alert    alert
	Received bool
	Detail   string
}

func (e *AlertError) Error() string {
	who := "local error"
	if e.Received {
		who = "remote error"
	}
	if e.Detail != "" {
		return fmt.Sprintf("tls: %s: %s: %s", who, e.Alert, e.Detail)
	}
	return fmt.Sprintf("tls: %s: %s", who, e.Alert)
}

func fail(a alert, format string, args ...any) error {
	return &AlertError{Alert: a, Detail: fmt.Sprintf(format, args...)}
}
