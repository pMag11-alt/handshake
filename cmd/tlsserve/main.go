// Command tlsserve is an HTTPS server on handshake's TLS 1.3 stack. Each
// response describes the connection it arrived on.
//
//	tlsserve -addr localhost:8443
//	curl --cacert handshake-cert.pem https://localhost:8443/
package main

import (
	"bufio"
	"flag"
	"fmt"
	"html"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pMag11-alt/handshake"
)

func main() {
	addr := flag.String("addr", "localhost:8443", "address to listen on")
	certFile := flag.String("cert", "", "PEM certificate chain (default: generate a self-signed one)")
	keyFile := flag.String("key", "", "PEM private key for -cert")
	keyType := flag.String("keytype", "ecdsa", "key for a generated certificate: ecdsa, ecdsa384 or rsa")
	writeCert := flag.String("write-cert", "handshake-cert.pem", "where to save a generated certificate, for clients to trust")
	keyLog := flag.String("keylog", "", "append secrets to this file in NSS key log format")
	verbose := flag.Bool("v", false, "log each handshake step")
	flag.Parse()

	cert, err := loadOrGenerate(*certFile, *keyFile, *keyType, *addr, *writeCert)
	if err != nil {
		log.Fatal(err)
	}
	cfg := &handshake.Config{Certificate: cert, NextProtos: []string{"http/1.1"}}
	if *keyLog != "" {
		f, err := os.OpenFile(*keyLog, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		cfg.KeyLogWriter = f
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on https://%s/", ln.Addr())
	for {
		raw, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		c := *cfg
		if *verbose {
			peer := raw.RemoteAddr().String()
			c.Trace = func(line string) { log.Printf("%s  %s", peer, line) }
		}
		go serve(handshake.Server(raw, &c))
	}
}

func loadOrGenerate(certFile, keyFile, keyType, addr, writeCert string) (*handshake.Certificate, error) {
	if certFile != "" {
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return nil, err
		}
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		return handshake.LoadCertificate(certPEM, keyPEM)
	}
	kt := map[string]handshake.KeyType{"ecdsa": handshake.KeyECDSAP256, "ecdsa384": handshake.KeyECDSAP384, "rsa": handshake.KeyRSA2048}[keyType]
	host, _, _ := net.SplitHostPort(addr)
	hosts := []string{"localhost", "127.0.0.1", "::1"}
	if host != "" && host != "localhost" && host != "127.0.0.1" {
		hosts = append(hosts, host)
	}
	cert, err := handshake.SelfSigned(kt, hosts...)
	if err != nil {
		return nil, err
	}
	certPEM, _, err := cert.PEM()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(writeCert, certPEM, 0o644); err != nil {
		return nil, err
	}
	log.Printf("generated a self-signed %s certificate for %s; trust it with --cacert %s", keyType, strings.Join(hosts, ", "), writeCert)
	return cert, nil
}

func serve(conn *handshake.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := conn.Handshake(); err != nil {
		log.Printf("%s: handshake failed: %v", conn.RemoteAddr(), err)
		return
	}
	r := bufio.NewReader(conn)
	requestLine, err := r.ReadString('\n')
	if err != nil {
		return
	}
	for {
		line, err := r.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	st := conn.ConnectionState()
	fields := strings.Fields(requestLine)
	path := "/"
	if len(fields) > 1 {
		path = fields[1]
	}
	var body string
	if strings.HasSuffix(path, ".txt") || path == "/plain" {
		body = fmt.Sprintf("TLS 1.3, %v, %v, %v\n", st.CipherSuite, st.Group, st.SignatureScheme)
	} else {
		body = page(st, conn.RemoteAddr().String())
	}
	ctype := "text/html; charset=utf-8"
	if strings.HasSuffix(path, ".txt") || path == "/plain" {
		ctype = "text/plain; charset=utf-8"
	}
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", ctype, len(body), body)
}

func page(st handshake.ConnectionState, peer string) string {
	retry := ""
	if st.HelloRetried {
		retry = " (after a HelloRetryRequest)"
	}
	row := func(k, v string) string {
		return "<tr><th>" + k + "</th><td>" + html.EscapeString(v) + "</td></tr>"
	}
	return `<!doctype html><meta charset="utf-8"><title>handshake</title>
<style>body{font:16px system-ui;max-width:640px;margin:48px auto;padding:0 16px}th{text-align:left;padding-right:24px;color:#555}td,th{padding:6px 0}</style>
<h1>Hello over TLS 1.3</h1>
<p>This response was encrypted by <b>handshake</b>, a TLS 1.3 stack written from scratch in Go.</p>
<table>` +
		row("Client", peer) +
		row("Cipher suite", st.CipherSuite.String()) +
		row("Key exchange", st.Group.String()+retry) +
		row("Server signature", st.SignatureScheme.String()) +
		row("ALPN", st.NegotiatedProto) +
		row("SNI", st.ServerName) +
		row("Handshake time", st.HandshakeDuration.Round(time.Microsecond).String()) +
		`</table>`
}
