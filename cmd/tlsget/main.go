// Command tlsget fetches an HTTPS URL over handshake's TLS 1.3 stack, like
// a tiny curl, and can narrate the handshake step by step.
//
//	tlsget -v https://example.com/
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/pMag11-alt/handshake"
)

func main() {
	verbose := flag.Bool("v", false, "narrate the handshake and show the certificate chain")
	insecure := flag.Bool("k", false, "skip certificate verification")
	include := flag.Bool("i", false, "include the HTTP response headers in the output")
	handshakeOnly := flag.Bool("handshake-only", false, "stop after the handshake; print the connection summary")
	caFile := flag.String("cacert", "", "PEM file of trusted roots (default: system trust store)")
	keyLog := flag.String("keylog", "", "append secrets to this file in NSS key log format (for Wireshark)")
	suite := flag.String("suite", "", "offer only this cipher suite: aes128, aes256 or chacha20")
	group := flag.String("group", "", "lead with this key exchange group: x25519, p256 or p384")
	alpn := flag.String("alpn", "http/1.1", "comma-separated ALPN protocols to offer")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: tlsget [flags] https://host[:port]/path\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(flag.Arg(0), options{*verbose, *insecure, *include, *handshakeOnly, *caFile, *keyLog, *suite, *group, *alpn}); err != nil {
		fmt.Fprintln(os.Stderr, "tlsget:", err)
		os.Exit(1)
	}
}

type options struct {
	verbose, insecure, include, handshakeOnly bool
	caFile, keyLog, suite, group, alpn        string
}

func run(rawURL string, o options) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("expected an https:// URL, got %q", rawURL)
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	cfg := &handshake.Config{ServerName: host, InsecureSkipVerify: o.insecure}
	if o.alpn != "" {
		cfg.NextProtos = strings.Split(o.alpn, ",")
	}
	start := time.Now()
	if o.verbose {
		cfg.Trace = func(line string) {
			fmt.Fprintf(os.Stderr, "%8.2fms  %s\n", float64(time.Since(start).Microseconds())/1000, line)
		}
	}
	if o.caFile != "" {
		data, err := os.ReadFile(o.caFile)
		if err != nil {
			return err
		}
		cfg.RootCAs = handshake.NewCertPool()
		if cfg.RootCAs.AddPEM(data) == 0 {
			return fmt.Errorf("no certificates in %s", o.caFile)
		}
	}
	if o.keyLog != "" {
		f, err := os.OpenFile(o.keyLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		cfg.KeyLogWriter = f
	}
	switch o.suite {
	case "":
	case "aes128":
		cfg.CipherSuites = []handshake.CipherSuite{handshake.TLS_AES_128_GCM_SHA256}
	case "aes256":
		cfg.CipherSuites = []handshake.CipherSuite{handshake.TLS_AES_256_GCM_SHA384}
	case "chacha20":
		cfg.CipherSuites = []handshake.CipherSuite{handshake.TLS_CHACHA20_POLY1305_SHA256}
	default:
		return fmt.Errorf("unknown suite %q", o.suite)
	}
	switch o.group {
	case "":
	case "x25519":
		cfg.CurvePreferences = []handshake.CurveID{handshake.X25519, handshake.P256, handshake.P384}
	case "p256":
		cfg.CurvePreferences = []handshake.CurveID{handshake.P256, handshake.X25519, handshake.P384}
	case "p384":
		cfg.CurvePreferences = []handshake.CurveID{handshake.P384, handshake.X25519, handshake.P256}
	default:
		return fmt.Errorf("unknown group %q", o.group)
	}

	tcp, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 15*time.Second)
	if err != nil {
		return err
	}
	if o.verbose {
		cfg.Trace(fmt.Sprintf("TCP connected to %s", tcp.RemoteAddr()))
	}
	conn := handshake.Client(tcp, cfg)
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := conn.Handshake(); err != nil {
		return err
	}
	st := conn.ConnectionState()
	if o.verbose || o.handshakeOnly {
		summarize(st)
	}
	if o.handshakeOnly {
		return nil
	}

	path := u.RequestURI()
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: tlsget/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, u.Host)
	if _, err := io.WriteString(conn, req); err != nil {
		return err
	}
	r := bufio.NewReader(conn)
	status, err := r.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading the response: %w", err)
	}
	if o.include {
		fmt.Print(status)
	}
	if o.verbose {
		fmt.Fprintf(os.Stderr, "\n< %s", status)
	}
	chunked := false
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		if o.include {
			fmt.Print(line)
		}
		if strings.EqualFold(strings.TrimSpace(line), "transfer-encoding: chunked") {
			chunked = true
		}
		if line == "\r\n" {
			break
		}
	}
	if chunked {
		return copyChunked(os.Stdout, r)
	}
	_, err = io.Copy(os.Stdout, r)
	return err
}

func summarize(st handshake.ConnectionState) {
	fmt.Fprintf(os.Stderr, "\nprotocol      TLS 1.3\n")
	fmt.Fprintf(os.Stderr, "cipher suite  %v\n", st.CipherSuite)
	fmt.Fprintf(os.Stderr, "key exchange  %v", st.Group)
	if st.HelloRetried {
		fmt.Fprintf(os.Stderr, " (after HelloRetryRequest)")
	}
	fmt.Fprintf(os.Stderr, "\nsignature     %v\n", st.SignatureScheme)
	if st.NegotiatedProto != "" {
		fmt.Fprintf(os.Stderr, "ALPN          %s\n", st.NegotiatedProto)
	}
	fmt.Fprintf(os.Stderr, "handshake     %s\n", st.HandshakeDuration.Round(time.Microsecond))
	chain := st.VerifiedChain
	if chain == nil {
		chain = st.PeerCertificates
	}
	for i, c := range chain {
		fmt.Fprintf(os.Stderr, "certificate   %d  %s\n", i, c.Subject)
		fmt.Fprintf(os.Stderr, "                 issued by %s, %s until %s\n", c.Issuer, c.SignatureAlgorithm, c.NotAfter.Format("2006-01-02"))
	}
}

// copyChunked decodes an HTTP/1.1 chunked body.
func copyChunked(w io.Writer, r *bufio.Reader) error {
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		var size int
		if _, err := fmt.Sscanf(strings.TrimSpace(strings.SplitN(line, ";", 2)[0]), "%x", &size); err != nil {
			return fmt.Errorf("bad chunk size %q", line)
		}
		if size == 0 {
			return nil
		}
		if _, err := io.CopyN(w, r, int64(size)); err != nil {
			return err
		}
		if _, err := r.ReadString('\n'); err != nil {
			return err
		}
	}
}
