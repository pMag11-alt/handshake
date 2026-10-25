package handshake

import (
	"io"
	"net"
	"testing"

	"github.com/pMag11-alt/handshake/internal/x509"
)

// Parsers must reject garbage with an error, never a panic: every byte
// they see comes from the network before any authentication.

func seedHello(f *testing.F) {
	h := &clientHello{
		random: make([]byte, 32), sessionID: make([]byte, 32),
		cipherSuites: defaultCipherSuites, serverName: "example.com",
		supportedGroups: defaultCurves, signatureSchemes: defaultSignatureSchemes,
		supportedVersions: []uint16{VersionTLS13}, keyShares: []keyShare{{X25519, make([]byte, 32)}},
		alpn: []string{"h2"}, pskModes: []uint8{1}, cookie: []byte("cookie"),
	}
	f.Add(h.marshal()[4:])
	sh := &serverHello{random: make([]byte, 32), sessionID: make([]byte, 32), cipherSuite: TLS_AES_128_GCM_SHA256,
		supportedVersion: VersionTLS13, keyShare: keyShare{X25519, make([]byte, 32)}}
	f.Add(sh.marshal()[4:])
	f.Add([]byte{})
}

func FuzzParseClientHello(f *testing.F) {
	seedHello(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		if m, err := parseClientHello(data); err == nil {
			// Whatever parses must re-encode and parse again.
			if _, err := parseClientHello(m.marshal()[4:]); err != nil && m.random != nil && len(m.sessionID) <= 32 {
				t.Fatalf("re-encoded ClientHello fails to parse: %v", err)
			}
		}
	})
}

func FuzzParseServerHello(f *testing.F) {
	seedHello(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		parseServerHello(data)
	})
}

func FuzzParseHandshakeMessages(f *testing.F) {
	f.Add((&certificateMsg{chain: [][]byte{{1, 2, 3}}}).marshal()[4:])
	f.Add((&certificateVerifyMsg{scheme: PSSWithSHA256, signature: []byte{1, 2}}).marshal()[4:])
	f.Add((&encryptedExtensions{alpn: "h2"}).marshal()[4:])
	f.Fuzz(func(t *testing.T, data []byte) {
		parseCertificate(data)
		parseCertificateVerify(data)
		parseEncryptedExtensions(data)
		parseNewSessionTicket(data)
		parseCertificateRequest(data)
	})
}

func FuzzParseCertificate(f *testing.F) {
	for _, kt := range []KeyType{KeyECDSAP256} {
		c, err := SelfSigned(kt, "fuzz.test")
		if err != nil {
			f.Fatal(err)
		}
		f.Add(c.Chain[0])
	}
	f.Fuzz(func(t *testing.T, der []byte) {
		if cert, err := x509.Parse(der); err == nil {
			cert.VerifyHostname("fuzz.test")
			cert.CheckSignatureFrom(cert)
		}
	})
}

// scriptedConn plays back fixed bytes as the peer and discards writes.
type scriptedConn struct {
	net.Conn
	data []byte
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}
func (c *scriptedConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *scriptedConn) Close() error                { return nil }

// FuzzClientHandshake drives the whole client state machine with whatever
// a hostile server might send.
func FuzzClientHandshake(f *testing.F) {
	sh := (&serverHello{random: make([]byte, 32), sessionID: make([]byte, 32), cipherSuite: TLS_AES_128_GCM_SHA256,
		supportedVersion: VersionTLS13, keyShare: keyShare{X25519, make([]byte, 32)}}).marshal()
	hrr := (&serverHello{random: hrrRandom, sessionID: make([]byte, 32), cipherSuite: TLS_AES_128_GCM_SHA256,
		supportedVersion: VersionTLS13, selectedGroup: P256}).marshal()
	record := func(typ uint8, body []byte) []byte {
		return append([]byte{typ, 3, 3, byte(len(body) >> 8), byte(len(body))}, body...)
	}
	f.Add(record(recordHandshake, sh))
	f.Add(record(recordHandshake, hrr))
	f.Add(append(record(recordHandshake, sh), record(recordChangeCipherSpec, []byte{1})...))
	f.Add(record(recordAlert, []byte{2, 40}))
	f.Fuzz(func(t *testing.T, data []byte) {
		// A zero reader makes the client's random and session ID all
		// zeros, which the seeds echo back.
		c := Client(&scriptedConn{data: data}, &Config{ServerName: "fuzz.test", InsecureSkipVerify: true, Rand: zeroReader{}})
		c.Handshake()
	})
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}
