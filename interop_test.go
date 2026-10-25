package handshake

// These tests talk to Go's crypto/tls, an independent implementation, in
// both directions. crypto/tls is only ever the peer; the code under test
// uses none of it.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	stdx509 "crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/pMag11-alt/handshake/internal/x509"
)

// stdServerCert makes an ECDSA certificate with crypto/x509.
func stdServerCert(t *testing.T) (stdtls.Certificate, *x509.Pool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &stdx509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "stdlib server"},
		DNSNames:     []string{"server.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     stdx509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []stdx509.ExtKeyUsage{stdx509.ExtKeyUsageServerAuth},
	}
	der, err := stdx509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.Parse(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewPool()
	pool.Add(leaf)
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestClientAgainstCryptoTLS(t *testing.T) {
	cert, pool := stdServerCert(t)
	cases := []struct {
		name   string
		server *stdtls.Config
		client *Config
		retry  bool
	}{
		{"defaults", &stdtls.Config{}, &Config{}, false},
		{"P-256 only forces a HelloRetryRequest", &stdtls.Config{CurvePreferences: []stdtls.CurveID{stdtls.CurveP256}}, &Config{}, true},
		{"P-384 only", &stdtls.Config{CurvePreferences: []stdtls.CurveID{stdtls.CurveP384}}, &Config{}, true},
		{"AES-256-GCM", &stdtls.Config{}, &Config{CipherSuites: []CipherSuite{TLS_AES_256_GCM_SHA384}}, false},
		{"ChaCha20-Poly1305", &stdtls.Config{}, &Config{CipherSuites: []CipherSuite{TLS_CHACHA20_POLY1305_SHA256}}, false},
		{"ALPN", &stdtls.Config{NextProtos: []string{"h2"}}, &Config{NextProtos: []string{"h2", "http/1.1"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, b := loopback(t)
			sc := c.server
			sc.Certificates = []stdtls.Certificate{cert}
			sc.MinVersion = stdtls.VersionTLS13
			server := stdtls.Server(b, sc)
			go func() {
				buf := make([]byte, 5)
				if _, err := io.ReadFull(server, buf); err == nil {
					server.Write(append([]byte("echo:"), buf...))
				}
			}()
			cc := c.client
			cc.ServerName = "server.test"
			cc.RootCAs = pool
			client := Client(a, cc)
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			if got := client.ConnectionState().HelloRetried; got != c.retry {
				t.Errorf("HelloRetried = %v", got)
			}
			if _, err := client.Write([]byte("hello")); err != nil {
				t.Fatal(err)
			}
			reply := make([]byte, 10)
			if _, err := io.ReadFull(client, reply); err != nil || string(reply) != "echo:hello" {
				t.Fatalf("reply %q, %v", reply, err)
			}
		})
	}
}

// crypto/tls rotates its keys when we send KeyUpdate and answers with its
// own, which we must follow.
func TestKeyUpdateWithCryptoTLS(t *testing.T) {
	cert, pool := stdServerCert(t)
	a, b := loopback(t)
	server := stdtls.Server(b, &stdtls.Config{Certificates: []stdtls.Certificate{cert}, MinVersion: stdtls.VersionTLS13})
	go io.Copy(server, server)
	client := Client(a, &Config{ServerName: "server.test", RootCAs: pool})
	for i := 0; i < 3; i++ {
		if err := client.KeyUpdate(); err != nil {
			t.Fatal(err)
		}
		msg := []byte("round trip after key update")
		client.Write(msg)
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(client, got); err != nil || string(got) != string(msg) {
			t.Fatalf("round %d: %q %v", i, got, err)
		}
	}
}

func TestServerAgainstCryptoTLS(t *testing.T) {
	for kt, cert := range certs(t) {
		certPEM, _, err := cert.PEM()
		if err != nil {
			t.Fatal(err)
		}
		roots := stdx509.NewCertPool()
		roots.AppendCertsFromPEM(certPEM)
		for _, suite := range defaultCipherSuites {
			for _, curve := range []stdtls.CurveID{stdtls.X25519, stdtls.CurveP256, stdtls.CurveP384} {
				a, b := loopback(t)
				server := Server(b, &Config{Certificate: cert, CipherSuites: []CipherSuite{suite}})
				go func() {
					buf := make([]byte, 4)
					if _, err := io.ReadFull(server, buf); err == nil {
						server.Write(buf)
					}
				}()
				client := stdtls.Client(a, &stdtls.Config{
					ServerName:       "server.test",
					RootCAs:          roots,
					MinVersion:       stdtls.VersionTLS13,
					CurvePreferences: []stdtls.CurveID{curve},
				})
				if err := client.Handshake(); err != nil {
					t.Fatalf("key %d, %v, %v: %v", kt, suite, curve, err)
				}
				st := client.ConnectionState()
				if CipherSuite(st.CipherSuite) != suite {
					t.Errorf("negotiated %v, want %v", CipherSuite(st.CipherSuite), suite)
				}
				client.Write([]byte("ping"))
				got := make([]byte, 4)
				if _, err := io.ReadFull(client, got); err != nil || string(got) != "ping" {
					t.Fatalf("echo: %q %v", got, err)
				}
				client.Close()
			}
		}
	}
}

// A TLS 1.2-only server is refused with protocol_version.
func TestRefusesTLS12(t *testing.T) {
	cert, pool := stdServerCert(t)
	a, b := loopback(t)
	server := stdtls.Server(b, &stdtls.Config{Certificates: []stdtls.Certificate{cert}, MaxVersion: stdtls.VersionTLS12})
	go server.Handshake()
	err := Client(a, &Config{ServerName: "server.test", RootCAs: pool}).Handshake()
	if err == nil {
		t.Fatal("handshake with a TLS 1.2 server succeeded")
	}
	t.Logf("as expected: %v", err)
}

var _ net.Conn = (*Conn)(nil)
