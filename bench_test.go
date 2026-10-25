package handshake

import (
	"io"
	"testing"
)

func BenchmarkHandshake(b *testing.B) {
	cases := []struct {
		name  string
		key   KeyType
		group CurveID
	}{
		{"X25519-ECDSA-P256", KeyECDSAP256, X25519},
		{"P256-ECDSA-P256", KeyECDSAP256, P256},
		{"X25519-RSA2048", KeyRSA2048, X25519},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			cert, err := SelfSigned(c.key, "server.test")
			if err != nil {
				b.Fatal(err)
			}
			pool, _ := cert.Pool()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				a, s := loopback(b)
				client := Client(a, &Config{ServerName: "server.test", RootCAs: pool, CurvePreferences: []CurveID{c.group}})
				server := Server(s, &Config{Certificate: cert})
				done := make(chan error)
				go func() { done <- server.Handshake() }()
				if err := client.Handshake(); err != nil {
					b.Fatal(err)
				}
				if err := <-done; err != nil {
					b.Fatal(err)
				}
				a.Close()
				s.Close()
			}
		})
	}
}

func BenchmarkThroughput(b *testing.B) {
	cert, err := SelfSigned(KeyECDSAP256, "server.test")
	if err != nil {
		b.Fatal(err)
	}
	pool, _ := cert.Pool()
	for _, suite := range defaultCipherSuites {
		b.Run(suite.String(), func(b *testing.B) {
			a, s := loopback(b)
			defer a.Close()
			defer s.Close()
			client := Client(a, &Config{ServerName: "server.test", RootCAs: pool, CipherSuites: []CipherSuite{suite}})
			server := Server(s, &Config{Certificate: cert})
			go io.Copy(io.Discard, server)
			if err := client.Handshake(); err != nil {
				b.Fatal(err)
			}
			buf := make([]byte, 1<<20)
			b.SetBytes(int64(len(buf)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := client.Write(buf); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
