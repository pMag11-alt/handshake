package handshake

import (
	"errors"
	"net"
	"time"

	"github.com/pMag11-alt/handshake/internal/ecc"
	"github.com/pMag11-alt/handshake/internal/pem"
	"github.com/pMag11-alt/handshake/internal/rsa"
	"github.com/pMag11-alt/handshake/internal/x509"
)

// KeyType selects the key for a generated certificate.
type KeyType int

const (
	KeyECDSAP256 KeyType = iota
	KeyECDSAP384
	KeyRSA2048
)

// SelfSigned mints a certificate valid for the given host names and IP
// addresses for 30 days, for development servers.
func SelfSigned(kt KeyType, hosts ...string) (*Certificate, error) {
	var priv any
	var err error
	switch kt {
	case KeyECDSAP256:
		priv, err = ecc.GenerateKey(ecc.P256)
	case KeyECDSAP384:
		priv, err = ecc.GenerateKey(ecc.P384)
	case KeyRSA2048:
		priv, err = rsa.GenerateKey(2048)
	default:
		return nil, errors.New("tls: unknown key type")
	}
	if err != nil {
		return nil, err
	}
	tmpl := x509.Template{
		CommonName: "handshake development certificate",
		NotBefore:  time.Now().Add(-time.Hour),
		NotAfter:   time.Now().AddDate(0, 0, 30),
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPs = append(tmpl.IPs, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateSelfSigned(tmpl, priv)
	if err != nil {
		return nil, err
	}
	return &Certificate{Chain: [][]byte{der}, PrivateKey: priv}, nil
}

// LoadCertificate reads a PEM certificate chain and a PEM private key
// (PKCS #8, PKCS #1 or SEC 1).
func LoadCertificate(certPEM, keyPEM []byte) (*Certificate, error) {
	cert := &Certificate{}
	for _, b := range pem.Decode(certPEM) {
		if b.Type == "CERTIFICATE" {
			cert.Chain = append(cert.Chain, b.Bytes)
		}
	}
	if len(cert.Chain) == 0 {
		return nil, errors.New("tls: no certificates in the PEM data")
	}
	key, err := x509.ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		return nil, err
	}
	cert.PrivateKey = key
	return cert, nil
}

// PEM returns the chain and key in PEM, e.g. to save a generated
// certificate or to trust it from another client.
func (c *Certificate) PEM() (certPEM, keyPEM []byte, err error) {
	for _, der := range c.Chain {
		certPEM = append(certPEM, pem.Encode(pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	pkcs8, err := x509.MarshalPKCS8(c.PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return certPEM, pem.Encode(pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}), nil
}

// Pool returns a trust pool containing just this certificate's leaf, so a
// client can trust a self-signed server.
func (c *Certificate) Pool() (*x509.Pool, error) {
	leaf, err := x509.Parse(c.Chain[0])
	if err != nil {
		return nil, err
	}
	p := x509.NewPool()
	p.Add(leaf)
	return p, nil
}

// CertPool is a set of trusted root certificates.
type CertPool = x509.Pool

// X509Certificate is a parsed certificate, as found in ConnectionState.
type X509Certificate = x509.Certificate

// NewCertPool returns an empty pool; add PEM certificates with AddPEM.
func NewCertPool() *CertPool { return x509.NewPool() }
