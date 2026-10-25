package handshake

import (
	"errors"
	"os"
	"sync"

	"github.com/pMag11-alt/handshake/internal/x509"
)

// Where operating systems keep their PEM trust bundles.
var rootBundlePaths = []string{
	"/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine, Arch
	"/etc/pki/tls/certs/ca-bundle.crt",   // Fedora, RHEL
	"/etc/ssl/ca-bundle.pem",             // openSUSE
	"/etc/ssl/cert.pem",                  // macOS, FreeBSD, OpenBSD
}

var (
	systemRootsOnce sync.Once
	systemRoots     *x509.Pool
	systemRootsErr  error
)

// SystemRoots loads the operating system's trust store, honouring
// SSL_CERT_FILE like OpenSSL does.
func SystemRoots() (*x509.Pool, error) {
	systemRootsOnce.Do(func() {
		paths := rootBundlePaths
		if f := os.Getenv("SSL_CERT_FILE"); f != "" {
			paths = []string{f}
		}
		for _, p := range paths {
			data, err := os.ReadFile(p)
			if err != nil {
				continue
			}
			pool := x509.NewPool()
			if pool.AddPEM(data) > 0 {
				systemRoots = pool
				return
			}
		}
		systemRootsErr = errors.New("tls: no system root certificates found; set Config.RootCAs or SSL_CERT_FILE")
	})
	return systemRoots, systemRootsErr
}
