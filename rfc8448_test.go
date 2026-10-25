package handshake

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/pMag11-alt/handshake/internal/x25519"
	"github.com/pMag11-alt/handshake/internal/x509"
)

// trace holds the labelled values of RFC 8448 section 3, "Simple 1-RTT
// Handshake", keyed as "heading / label", e.g.
// "{server}  derive secret "tls13 c hs traffic" / expanded". A key that
// repeats gets "#2", "#3"... on its later occurrences.
type trace map[string][]byte

var (
	headingRE = regexp.MustCompile(`^   (\{(?:client|server)\}  .*?):?$`)
	valueRE   = regexp.MustCompile(`^      (.+?) \((\d+) octets\):\s*(.*)$`)
	hexRE     = regexp.MustCompile(`^\s+([0-9a-f]{2}( [0-9a-f]{2})*)\s*$`)
)

func loadTrace(t *testing.T) trace {
	t.Helper()
	f, err := os.Open("testdata/rfc8448.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := trace{}
	inSection := false
	heading, label := "", ""
	want := 0
	var cur []byte
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "3.  Simple 1-RTT Handshake") {
			inSection = true
			continue
		}
		if strings.HasPrefix(line, "4.  Resumed 0-RTT Handshake") {
			break
		}
		if !inSection {
			continue
		}
		if m := headingRE.FindStringSubmatch(line); m != nil {
			heading = m[1]
			continue
		}
		if m := valueRE.FindStringSubmatch(line); m != nil {
			label = m[1]
			want, _ = strconv.Atoi(m[2])
			cur = nil
			line = "         " + m[3]
		}
		if len(cur) < want {
			if m := hexRE.FindStringSubmatch(line); m != nil {
				b, _ := hex.DecodeString(strings.ReplaceAll(m[1], " ", ""))
				cur = append(cur, b...)
				if len(cur) == want {
					key := heading + " / " + label
					for n := 2; ; n++ {
						if _, taken := tr[key]; !taken {
							break
						}
						key = heading + " / " + label + "#" + strconv.Itoa(n)
					}
					tr[key] = cur
				}
			}
		}
	}
	return tr
}

func (tr trace) get(t *testing.T, key string) []byte {
	t.Helper()
	v, ok := tr[key]
	if !ok {
		t.Fatalf("trace has no %q", key)
	}
	return v
}

func TestRFC8448SimpleHandshake(t *testing.T) {
	tr := loadTrace(t)
	s := suites[TLS_AES_128_GCM_SHA256]

	// (EC)DHE: both sides compute the same shared secret.
	clientPriv := tr.get(t, "{client}  create an ephemeral x25519 key pair / private key")
	serverPub := tr.get(t, "{server}  create an ephemeral x25519 key pair / public key")
	shared, err := x25519.X25519(clientPriv, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shared, tr.get(t, `{server}  extract secret "handshake" / IKM`)) {
		t.Fatalf("shared secret %x", shared)
	}

	ch := tr.get(t, "{client}  construct a ClientHello handshake message / ClientHello")
	sh := tr.get(t, "{server}  construct a ServerHello handshake message / ServerHello")
	hello, err := parseClientHello(ch[4:])
	if err != nil {
		t.Fatal(err)
	}
	if hello.serverName != "server" || len(hello.keyShares) != 1 || hello.keyShares[0].group != X25519 {
		t.Fatalf("parsed ClientHello: %+v", hello)
	}
	shMsg, err := parseServerHello(sh[4:])
	if err != nil || shMsg.cipherSuite != TLS_AES_128_GCM_SHA256 || shMsg.supportedVersion != VersionTLS13 {
		t.Fatalf("parsed ServerHello: %+v %v", shMsg, err)
	}

	transcript := s.newHash()
	transcript.Write(ch)
	transcript.Write(sh)
	ks := &schedule{suite: s}
	ks.handshake(shared, transcript)
	check := func(name string, got []byte, key string) {
		t.Helper()
		if want := tr.get(t, key); !bytes.Equal(got, want) {
			t.Errorf("%s:\n got %x\nwant %x", name, got, want)
		}
	}
	check("handshake secret", ks.handshakeSecret, `{server}  extract secret "handshake" / secret`)
	check("client handshake traffic", ks.clientHandshakeTraffic, `{server}  derive secret "tls13 c hs traffic" / expanded`)
	check("server handshake traffic", ks.serverHandshakeTraffic, `{server}  derive secret "tls13 s hs traffic" / expanded`)
	key, iv := s.trafficKeys(ks.serverHandshakeTraffic)
	check("server handshake key", key, "{server}  derive write traffic keys for handshake data / key expanded")
	check("server handshake iv", iv, "{server}  derive write traffic keys for handshake data / iv expanded")

	// Decrypt the server's encrypted flight with our record layer.
	var in halfConn
	if err := in.setSecret(s, ks.serverHandshakeTraffic); err != nil {
		t.Fatal(err)
	}
	// The first "send handshake record" is the plaintext ServerHello.
	record := tr.get(t, "{server}  send handshake record / complete record#2")
	if record[0] != recordApplicationData {
		t.Fatalf("expected the encrypted record, got type %d", record[0])
	}
	typ, flight, err := in.open(record[:5], record[5:])
	if err != nil || typ != recordHandshake {
		t.Fatalf("decrypting the server flight: type %d, %v", typ, err)
	}
	check("server flight", flight, "{server}  send handshake record / payload#2")

	ee := tr.get(t, "{server}  construct an EncryptedExtensions handshake message / EncryptedExtensions")
	certMsg := tr.get(t, "{server}  construct a Certificate handshake message / Certificate")
	cvMsg := tr.get(t, "{server}  construct a CertificateVerify handshake message / CertificateVerify")
	finMsg := tr.get(t, "{server}  construct a Finished handshake message / Finished")
	if !bytes.Equal(flight, bytes.Join([][]byte{ee, certMsg, cvMsg, finMsg}, nil)) {
		t.Fatal("decrypted flight is not EE || Certificate || CertificateVerify || Finished")
	}

	// The server's RSA certificate verifies its RSA-PSS CertificateVerify.
	transcript.Write(ee)
	transcript.Write(certMsg)
	cm, err := parseCertificate(certMsg[4:])
	if err != nil || len(cm.chain) != 1 {
		t.Fatalf("Certificate: %v", err)
	}
	leaf, err := x509.Parse(cm.chain[0])
	if err != nil {
		t.Fatal(err)
	}
	cv, err := parseCertificateVerify(cvMsg[4:])
	if err != nil || cv.scheme != PSSWithSHA256 {
		t.Fatalf("CertificateVerify: %v %v", cv, err)
	}
	if err := verifyCertificateVerify(cv.scheme, leaf.PublicKey, signedMessage(serverSignatureContext, transcript.Sum(nil)), cv.signature); err != nil {
		t.Fatalf("CertificateVerify signature: %v", err)
	}
	transcript.Write(cvMsg)
	check("server Finished", s.finished(ks.serverHandshakeTraffic, transcript), `{server}  calculate finished "tls13 finished" / finished`)
	transcript.Write(finMsg)

	ks.application(transcript)
	check("master secret", ks.masterSecret, `{server}  extract secret "master" / secret`)
	check("client application traffic", ks.clientAppTraffic, `{server}  derive secret "tls13 c ap traffic" / expanded`)
	check("server application traffic", ks.serverAppTraffic, `{server}  derive secret "tls13 s ap traffic" / expanded`)
	check("exporter master", ks.exporterMaster, `{server}  derive secret "tls13 exp master" / expanded`)

	// Our client Finished, encrypted, is byte-identical to the trace.
	clientFin := marshalFinished(s.finished(ks.clientHandshakeTraffic, transcript))
	check("client Finished", clientFin, "{client}  construct a Finished handshake message / Finished")
	var out halfConn
	if err := out.setSecret(s, ks.clientHandshakeTraffic); err != nil {
		t.Fatal(err)
	}
	check("client Finished record", out.seal(recordHandshake, clientFin), "{client}  send handshake record / complete record#2")

	// Application data in both directions, then close_notify alerts.
	if err := out.setSecret(s, ks.clientAppTraffic); err != nil {
		t.Fatal(err)
	}
	if err := in.setSecret(s, ks.serverAppTraffic); err != nil {
		t.Fatal(err)
	}
	// The server's NewSessionTicket is the first record under its keys.
	ticketRec := tr.get(t, "{server}  send handshake record / complete record#3")
	typ, nst, err := in.open(ticketRec[:5], ticketRec[5:])
	if err != nil || typ != recordHandshake || nst[0] != typeNewSessionTicket {
		t.Fatalf("ticket record: %v", err)
	}
	if ticket, err := parseNewSessionTicket(nst[4:]); err != nil || ticket.lifetime != 30 {
		t.Fatalf("NewSessionTicket: %+v %v", ticket, err)
	}
	payload := tr.get(t, "{client}  send application_data record / payload")
	check("client application record", out.seal(recordApplicationData, payload), "{client}  send application_data record / complete record")
	srv := tr.get(t, "{server}  send application_data record / complete record")
	typ, data, err := in.open(srv[:5], srv[5:])
	if err != nil || typ != recordApplicationData || !bytes.Equal(data, payload) {
		t.Fatalf("server application record: %v", err)
	}
	check("client close_notify record", out.seal(recordAlert, []byte{1, 0}), "{client}  send alert record / complete record")
}
