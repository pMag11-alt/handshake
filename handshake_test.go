package handshake

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	certOnce  sync.Once
	testCerts map[KeyType]*Certificate
)

func certs(t *testing.T) map[KeyType]*Certificate {
	t.Helper()
	certOnce.Do(func() {
		testCerts = map[KeyType]*Certificate{}
		for _, kt := range []KeyType{KeyECDSAP256, KeyECDSAP384, KeyRSA2048} {
			c, err := SelfSigned(kt, "server.test", "127.0.0.1")
			if err != nil {
				panic(err)
			}
			testCerts[kt] = c
		}
	})
	return testCerts
}

// loopback returns the two ends of a TCP connection on 127.0.0.1. Real
// sockets matter: their buffers let both sides write at once, which
// net.Pipe does not.
func loopback(t testing.TB) (net.Conn, net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	a, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b := <-accepted
	t.Cleanup(func() { a.Close(); b.Close() })
	return a, b
}

// pair runs a handshake between our client and our server.
func pair(t *testing.T, clientCfg, serverCfg *Config) (*Conn, *Conn, error, error) {
	t.Helper()
	a, b := loopback(t)
	client, server := Client(a, clientCfg), Server(b, serverCfg)
	var serverErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverErr = server.Handshake()
		if serverErr != nil {
			b.Close()
		}
	}()
	clientErr := client.Handshake()
	if clientErr != nil {
		a.Close()
	}
	wg.Wait()
	return client, server, clientErr, serverErr
}

func clientConfigFor(t *testing.T, cert *Certificate) *Config {
	pool, err := cert.Pool()
	if err != nil {
		t.Fatal(err)
	}
	return &Config{ServerName: "server.test", RootCAs: pool}
}

func TestHandshakeMatrix(t *testing.T) {
	for kt, cert := range certs(t) {
		for _, suite := range defaultCipherSuites {
			for _, group := range defaultCurves {
				name := fmt.Sprintf("%v/%v/key%d", suite, group, kt)
				t.Run(name, func(t *testing.T) {
					cc := clientConfigFor(t, cert)
					cc.CipherSuites = []CipherSuite{suite}
					cc.CurvePreferences = []CurveID{group}
					sc := &Config{Certificate: cert}
					client, server, cerr, serr := pair(t, cc, sc)
					if cerr != nil || serr != nil {
						t.Fatalf("client: %v, server: %v", cerr, serr)
					}
					st := client.ConnectionState()
					if st.CipherSuite != suite || st.Group != group {
						t.Fatalf("negotiated %v %v", st.CipherSuite, st.Group)
					}
					echo(t, client, server, []byte("hello over "+name))
				})
			}
		}
	}
}

// echo sends data both ways and checks it arrives intact.
func echo(t *testing.T, client, server *Conn, data []byte) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		buf := make([]byte, len(data))
		if _, err := io.ReadFull(server, buf); err != nil {
			done <- err
			return
		}
		_, err := server.Write(buf)
		done <- err
	}()
	if _, err := client.Write(data); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(data))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("echoed data differs")
	}
}

// A client that leads with X25519 against a server that only accepts
// P-384 must go through a HelloRetryRequest.
func TestHelloRetryRequest(t *testing.T) {
	cert := certs(t)[KeyECDSAP256]
	cc := clientConfigFor(t, cert)
	sc := &Config{Certificate: cert, CurvePreferences: []CurveID{P384}}
	client, server, cerr, serr := pair(t, cc, sc)
	if cerr != nil || serr != nil {
		t.Fatalf("client: %v, server: %v", cerr, serr)
	}
	st := client.ConnectionState()
	if !st.HelloRetried || st.Group != P384 {
		t.Fatalf("HelloRetried=%v group=%v", st.HelloRetried, st.Group)
	}
	echo(t, client, server, []byte("after a retry"))
}

func TestLargeTransfersAndKeyUpdate(t *testing.T) {
	cert := certs(t)[KeyECDSAP256]
	client, server, cerr, serr := pair(t, clientConfigFor(t, cert), &Config{Certificate: cert})
	if cerr != nil || serr != nil {
		t.Fatalf("client: %v, server: %v", cerr, serr)
	}
	big := bytes.Repeat([]byte("0123456789abcdef"), 40000) // 640 KB, many records
	echo(t, client, server, big)
	// KeyUpdate needs the peer to read the request, so run echo after it.
	go func() { client.KeyUpdate() }()
	echo(t, client, server, []byte("after key update"))
	before := client.in.secret
	echo(t, client, server, []byte("both directions rotated"))
	if bytes.Equal(before, client.out.secret) {
		t.Fatal("client write keys were not rotated")
	}
}

func TestCloseNotify(t *testing.T) {
	cert := certs(t)[KeyECDSAP256]
	client, server, cerr, serr := pair(t, clientConfigFor(t, cert), &Config{Certificate: cert})
	if cerr != nil || serr != nil {
		t.Fatalf("client: %v, server: %v", cerr, serr)
	}
	go client.Close()
	if _, err := server.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("expected io.EOF after close_notify, got %v", err)
	}
}

func TestALPN(t *testing.T) {
	cert := certs(t)[KeyECDSAP256]
	cc := clientConfigFor(t, cert)
	cc.NextProtos = []string{"h2", "http/1.1"}
	client, _, cerr, serr := pair(t, cc, &Config{Certificate: cert, NextProtos: []string{"http/1.1"}})
	if cerr != nil || serr != nil {
		t.Fatalf("client: %v, server: %v", cerr, serr)
	}
	if p := client.ConnectionState().NegotiatedProto; p != "http/1.1" {
		t.Fatalf("ALPN chose %q", p)
	}
	cc = clientConfigFor(t, cert)
	cc.NextProtos = []string{"h2"}
	_, _, cerr, serr = pair(t, cc, &Config{Certificate: cert, NextProtos: []string{"http/1.1"}})
	var ae *AlertError
	if !errors.As(serr, &ae) || ae.Alert != alertNoApplicationProtocol {
		t.Fatalf("expected no_application_protocol, got %v / %v", cerr, serr)
	}
}

func TestVerificationFailures(t *testing.T) {
	cert := certs(t)[KeyECDSAP256]
	other := certs(t)[KeyECDSAP384]

	cases := []struct {
		name string
		cfg  *Config
		want alert
	}{
		{"untrusted", func() *Config { c := clientConfigFor(t, other); return c }(), alertUnknownCA},
		{"wrong name", func() *Config { c := clientConfigFor(t, cert); c.ServerName = "evil.test"; return c }(), alertBadCertificate},
		{"expired", func() *Config {
			c := clientConfigFor(t, cert)
			c.Time = func() time.Time { return time.Now().AddDate(1, 0, 0) }
			return c
		}(), alertCertificateExpired},
	}
	for _, c := range cases {
		_, _, cerr, _ := pair(t, c.cfg, &Config{Certificate: cert})
		var ae *AlertError
		if !errors.As(cerr, &ae) || ae.Alert != c.want {
			t.Errorf("%s: got %v, want %v", c.name, cerr, c.want)
		}
	}
	insecure := &Config{InsecureSkipVerify: true}
	if _, _, cerr, serr := pair(t, insecure, &Config{Certificate: other}); cerr != nil || serr != nil {
		t.Errorf("InsecureSkipVerify: %v / %v", cerr, serr)
	}
}

func TestNoCommonSuiteOrGroup(t *testing.T) {
	cert := certs(t)[KeyECDSAP256]
	cc := clientConfigFor(t, cert)
	cc.CipherSuites = []CipherSuite{TLS_CHACHA20_POLY1305_SHA256}
	_, _, _, serr := pair(t, cc, &Config{Certificate: cert, CipherSuites: []CipherSuite{TLS_AES_128_GCM_SHA256}})
	if serr == nil || !strings.Contains(serr.Error(), "handshake_failure") {
		t.Errorf("suite mismatch: %v", serr)
	}
	cc = clientConfigFor(t, cert)
	cc.CurvePreferences = []CurveID{X25519}
	_, _, _, serr = pair(t, cc, &Config{Certificate: cert, CurvePreferences: []CurveID{P256}})
	if serr == nil || !strings.Contains(serr.Error(), "handshake_failure") {
		t.Errorf("group mismatch: %v", serr)
	}
}

func TestKeyLog(t *testing.T) {
	cert := certs(t)[KeyECDSAP256]
	var buf bytes.Buffer
	cc := clientConfigFor(t, cert)
	cc.KeyLogWriter = &buf
	if _, _, cerr, serr := pair(t, cc, &Config{Certificate: cert}); cerr != nil || serr != nil {
		t.Fatal(cerr, serr)
	}
	for _, label := range []string{"CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET"} {
		if !strings.Contains(buf.String(), label+" ") {
			t.Errorf("key log is missing %s", label)
		}
	}
}
