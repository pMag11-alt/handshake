package x509

import (
	stdx509 "crypto/x509"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pMag11-alt/handshake/internal/ecc"
	"github.com/pMag11-alt/handshake/internal/pem"
	"github.com/pMag11-alt/handshake/internal/rsa"
)

// The chains in testdata were captured on this date; verifying "as of"
// then keeps the tests meaningful after the certificates expire.
var captured = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func loadChain(t *testing.T, name string) []*Certificate {
	t.Helper()
	data, err := os.ReadFile("testdata/chain-" + name + ".pem")
	if err != nil {
		t.Fatal(err)
	}
	var certs []*Certificate
	for _, b := range pem.Decode(data) {
		c, err := Parse(b.Bytes)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		certs = append(certs, c)
	}
	return certs
}

func roots(t *testing.T) *Pool {
	t.Helper()
	data, err := os.ReadFile("testdata/roots.pem")
	if err != nil {
		t.Fatal(err)
	}
	p := NewPool()
	if p.AddPEM(data) == 0 {
		t.Fatal("no roots parsed")
	}
	return p
}

func TestRealChainsVerify(t *testing.T) {
	pool := roots(t)
	for _, host := range []string{"github.com", "letsencrypt.org", "www.google.com", "www.cloudflare.com"} {
		certs := loadChain(t, host)
		chain, err := certs[0].Verify(VerifyOptions{Roots: pool, Intermediates: certs[1:], DNSName: host, CurrentTime: captured})
		if err != nil {
			t.Errorf("%s: %v", host, err)
			continue
		}
		names := []string{}
		for _, c := range chain {
			names = append(names, c.Subject.CommonName)
		}
		t.Logf("%s: %s", host, strings.Join(names, " -> "))
	}
}

func TestChainFailures(t *testing.T) {
	pool := roots(t)
	certs := loadChain(t, "github.com")
	opts := VerifyOptions{Roots: pool, Intermediates: certs[1:], DNSName: "github.com", CurrentTime: captured}

	wrongHost := opts
	wrongHost.DNSName = "example.com"
	if _, err := certs[0].Verify(wrongHost); err == nil {
		t.Error("accepted the wrong host name")
	}
	expired := opts
	expired.CurrentTime = captured.AddDate(3, 0, 0)
	if _, err := certs[0].Verify(expired); err == nil {
		t.Error("accepted an expired certificate")
	}
	missing := opts
	missing.Intermediates = nil
	if _, err := certs[0].Verify(missing); err == nil {
		t.Error("built a chain without the intermediate")
	}
	tampered := *certs[0]
	tampered.Signature = append([]byte(nil), certs[0].Signature...)
	tampered.Signature[len(tampered.Signature)-3] ^= 1
	if _, err := tampered.Verify(opts); err == nil {
		t.Error("accepted a tampered signature")
	}
	if _, err := certs[0].Verify(VerifyOptions{Roots: NewPool(), Intermediates: certs[1:], CurrentTime: captured}); err == nil {
		t.Error("verified with no trusted roots")
	}
}

// Every certificate in the system trust store parses, and agrees with
// crypto/x509 on the fields we use.
func TestSystemRootsMatchStdlib(t *testing.T) {
	var data []byte
	for _, path := range []string{"/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"} {
		if d, err := os.ReadFile(path); err == nil {
			data = d
			break
		}
	}
	if data == nil {
		t.Skip("no system CA bundle")
	}
	n := 0
	for _, b := range pem.Decode(data) {
		ours, err := Parse(b.Bytes)
		if err != nil {
			t.Errorf("parse: %v", err)
			continue
		}
		std, err := stdx509.ParseCertificate(b.Bytes)
		if err != nil {
			continue
		}
		n++
		if ours.Subject.CommonName != std.Subject.CommonName || ours.SerialNumber.Cmp(std.SerialNumber) != 0 ||
			!ours.NotBefore.Equal(std.NotBefore) || !ours.NotAfter.Equal(std.NotAfter) || ours.IsCA != std.IsCA {
			t.Errorf("%q: fields differ from crypto/x509", std.Subject.CommonName)
		}
		// Roots are self-signed; check the signature wherever we support
		// the algorithm and key type.
		if ours.PublicKey != nil && ours.SignatureAlgorithm != UnknownSignatureAlgorithm && string(ours.Issuer.Raw) == string(ours.Subject.Raw) {
			if err := ours.CheckSignatureFrom(ours); err != nil {
				t.Errorf("%q: self-signature: %v", std.Subject.CommonName, err)
			}
		}
	}
	t.Logf("compared %d certificates", n)
}

func TestSelfSignedRoundTrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, _ := ecc.GenerateKey(ecc.P256)
	for _, key := range []any{rsaKey, ecKey} {
		tmpl := Template{
			CommonName: "handshake test",
			DNSNames:   []string{"localhost", "*.example.test"},
			IPs:        []net.IP{net.ParseIP("127.0.0.1")},
			NotBefore:  captured.Add(-time.Hour),
			NotAfter:   captured.AddDate(0, 0, 30),
		}
		der, err := CreateSelfSigned(tmpl, key)
		if err != nil {
			t.Fatal(err)
		}
		std, err := stdx509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("crypto/x509 cannot parse our certificate: %v", err)
		}
		if err := std.CheckSignature(std.SignatureAlgorithm, std.RawTBSCertificate, std.Signature); err != nil {
			t.Fatalf("crypto/x509 rejects our signature: %v", err)
		}
		if err := std.VerifyHostname("api.example.test"); err != nil {
			t.Fatal(err)
		}
		ours, err := Parse(der)
		if err != nil {
			t.Fatal(err)
		}
		pool := NewPool()
		pool.Add(ours)
		for _, host := range []string{"localhost", "api.example.test", "127.0.0.1"} {
			if _, err := ours.Verify(VerifyOptions{Roots: pool, DNSName: host, CurrentTime: captured}); err != nil {
				t.Errorf("%s: %v", host, err)
			}
		}
		pkcs8, err := MarshalPKCS8(key)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := stdx509.ParsePKCS8PrivateKey(pkcs8); err != nil {
			t.Fatalf("crypto/x509 cannot parse our PKCS #8: %v", err)
		}
		back, err := ParsePrivateKeyPEM(pem.Encode(pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
		if err != nil {
			t.Fatal(err)
		}
		switch k := back.(type) {
		case *rsa.PrivateKey:
			if k.N.Cmp(rsaKey.N) != 0 {
				t.Fatal("RSA key did not round-trip")
			}
		case *ecc.PrivateKey:
			if k.D.Cmp(ecKey.D) != 0 {
				t.Fatal("EC key did not round-trip")
			}
		}
	}
}

func TestHostnameMatching(t *testing.T) {
	cases := []struct {
		pattern, host string
		ok            bool
	}{
		{"example.com", "example.com", true},
		{"example.com", "EXAMPLE.com.", true},
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "a.b.example.com", false},
		{"*.example.com", "example.com", false},
		{"*.com", "example.com", false},
		{"w*.example.com", "www.example.com", false},
	}
	for _, c := range cases {
		cert := &Certificate{DNSNames: []string{c.pattern}}
		if err := cert.VerifyHostname(c.host); (err == nil) != c.ok {
			t.Errorf("%s vs %s: got %v", c.pattern, c.host, err)
		}
	}
}
