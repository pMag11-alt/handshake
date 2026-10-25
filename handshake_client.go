package handshake

import (
	"bytes"
	"io"
	"slices"
	"strings"

	"github.com/pMag11-alt/handshake/internal/hmac"
	"github.com/pMag11-alt/handshake/internal/x509"
)

func (c *Conn) clientHandshake() error {
	cfg := c.config
	rand := cfg.rand()
	curves := cfg.curves()

	hello := &clientHello{
		random:            make([]byte, 32),
		sessionID:         make([]byte, 32),
		cipherSuites:      cfg.cipherSuites(),
		serverName:        cfg.ServerName,
		supportedGroups:   curves,
		signatureSchemes:  defaultSignatureSchemes,
		supportedVersions: []uint16{VersionTLS13},
		alpn:              cfg.NextProtos,
		pskModes:          []uint8{1}, // psk_dhe_ke, so servers will issue tickets
	}
	if _, err := io.ReadFull(rand, hello.random); err != nil {
		return err
	}
	// A non-empty legacy_session_id puts the server in middlebox
	// compatibility mode (RFC 8446 appendix D.4).
	if _, err := io.ReadFull(rand, hello.sessionID); err != nil {
		return err
	}
	c.clientRandom = hello.random
	kx, err := newKeyExchange(curves[0], rand)
	if err != nil {
		return err
	}
	hello.keyShares = []keyShare{{curves[0], kx.public()}}

	ch1 := hello.marshal()
	if err := c.writeHandshake(ch1); err != nil {
		return err
	}
	c.tracef("-> ClientHello: SNI=%q suites=%v groups=%v key share=%v", hello.serverName, hello.cipherSuites, curves, curves[0])

	_, shRaw, err := c.expect(typeServerHello, nil)
	if err != nil {
		return err
	}
	sh, err := c.checkServerHello(hello, shRaw)
	if err != nil {
		return err
	}
	s := suites[sh.cipherSuite]
	transcript := s.newHash()
	transcript.Write(ch1)

	sentCCS := false
	if sh.isHelloRetry() {
		// The first ClientHello is replaced by a synthetic message_hash.
		digest := s.newHash()
		digest.Write(ch1)
		sum := digest.Sum(nil)
		transcript = s.newHash()
		transcript.Write([]byte{typeMessageHash, 0, 0, byte(len(sum))})
		transcript.Write(sum)
		transcript.Write(shRaw)

		g := sh.selectedGroup
		if !slices.Contains(curves, g) || g == kx.group() {
			return fail(alertIllegalParameter, "HelloRetryRequest selected group %v", g)
		}
		c.tracef("<- HelloRetryRequest: server wants a %v key share", g)
		if kx, err = newKeyExchange(g, rand); err != nil {
			return err
		}
		hello.keyShares = []keyShare{{g, kx.public()}}
		hello.cookie = sh.cookie
		c.ccsAllowed = true
		if err := c.writeRecord(recordChangeCipherSpec, []byte{1}); err != nil {
			return err
		}
		sentCCS = true
		ch2 := hello.marshal()
		if err := c.writeHandshake(ch2); err != nil {
			return err
		}
		transcript.Write(ch2)
		c.tracef("-> ClientHello (retry) with a %v key share", g)

		retrySuite := sh.cipherSuite
		if _, shRaw, err = c.expect(typeServerHello, nil); err != nil {
			return err
		}
		if sh, err = c.checkServerHello(hello, shRaw); err != nil {
			return err
		}
		if sh.isHelloRetry() {
			return fail(alertUnexpectedMessage, "second HelloRetryRequest")
		}
		if sh.cipherSuite != retrySuite {
			return fail(alertIllegalParameter, "cipher suite changed after HelloRetryRequest")
		}
		c.state.HelloRetried = true
	}
	transcript.Write(shRaw)
	if sh.keyShare.group != kx.group() {
		return fail(alertIllegalParameter, "server key share for %v, we sent %v", sh.keyShare.group, kx.group())
	}
	shared, err := kx.shared(sh.keyShare.data)
	if err != nil {
		return fail(alertIllegalParameter, "bad server key share: %v", err)
	}
	c.tracef("<- ServerHello: %v, %v", sh.cipherSuite, kx.group())

	ks := &schedule{suite: s}
	ks.handshake(shared, transcript)
	c.keyLog("CLIENT_HANDSHAKE_TRAFFIC_SECRET", ks.clientHandshakeTraffic)
	c.keyLog("SERVER_HANDSHAKE_TRAFFIC_SECRET", ks.serverHandshakeTraffic)
	if err := c.setReadSecret(s, ks.serverHandshakeTraffic); err != nil {
		return err
	}
	c.ccsAllowed = true

	eeBody, _, err := c.expect(typeEncryptedExtensions, transcript)
	if err != nil {
		return err
	}
	ee, err := parseEncryptedExtensions(eeBody)
	if err != nil {
		return err
	}
	if ee.alpn != "" && !slices.Contains(cfg.NextProtos, ee.alpn) {
		return fail(alertIllegalParameter, "server chose unoffered protocol %q", ee.alpn)
	}
	c.tracef("<- EncryptedExtensions (ALPN %q)", ee.alpn)

	typ, body, raw, err := c.readHandshake()
	if err != nil {
		return err
	}
	var certRequest *certificateRequestMsg
	if typ == typeCertificateRequest {
		if certRequest, err = parseCertificateRequest(body); err != nil {
			return err
		}
		transcript.Write(raw)
		c.tracef("<- CertificateRequest (we will answer with no certificate)")
		if typ, body, raw, err = c.readHandshake(); err != nil {
			return err
		}
	}
	if typ != typeCertificate {
		return fail(alertUnexpectedMessage, "expected Certificate, got message %d", typ)
	}
	transcript.Write(raw)
	certMsg, err := parseCertificate(body)
	if err != nil {
		return err
	}
	if err := c.verifyServerCertificates(certMsg.chain); err != nil {
		return err
	}

	cvBody, cvRaw, err := c.expect(typeCertificateVerify, nil)
	if err != nil {
		return err
	}
	cv, err := parseCertificateVerify(cvBody)
	if err != nil {
		return err
	}
	if !slices.Contains(defaultSignatureSchemes, cv.scheme) {
		return fail(alertIllegalParameter, "server used unoffered signature scheme %v", cv.scheme)
	}
	signed := signedMessage(serverSignatureContext, transcript.Sum(nil))
	if err := verifyCertificateVerify(cv.scheme, c.state.PeerCertificates[0].PublicKey, signed, cv.signature); err != nil {
		return fail(alertDecryptError, "CertificateVerify: %v", err)
	}
	transcript.Write(cvRaw)
	c.state.SignatureScheme = cv.scheme
	c.tracef("<- CertificateVerify: %v signature over the transcript is valid", cv.scheme)

	expected := s.finished(ks.serverHandshakeTraffic, transcript)
	finBody, finRaw, err := c.expect(typeFinished, nil)
	if err != nil {
		return err
	}
	if !hmac.Equal(finBody, expected) {
		return fail(alertDecryptError, "server Finished does not match the transcript")
	}
	transcript.Write(finRaw)
	c.tracef("<- Finished: server's transcript MAC matches")

	ks.application(transcript)
	c.keyLog("CLIENT_TRAFFIC_SECRET_0", ks.clientAppTraffic)
	c.keyLog("SERVER_TRAFFIC_SECRET_0", ks.serverAppTraffic)
	c.keyLog("EXPORTER_SECRET", ks.exporterMaster)
	if err := c.setReadSecret(s, ks.serverAppTraffic); err != nil {
		return err
	}

	if !sentCCS {
		if err := c.writeRecord(recordChangeCipherSpec, []byte{1}); err != nil {
			return err
		}
	}
	if err := c.out.setSecret(s, ks.clientHandshakeTraffic); err != nil {
		return err
	}
	var flight [][]byte
	if certRequest != nil {
		empty := (&certificateMsg{context: certRequest.context}).marshal()
		transcript.Write(empty)
		flight = append(flight, empty)
	}
	fin := marshalFinished(s.finished(ks.clientHandshakeTraffic, transcript))
	flight = append(flight, fin)
	if err := c.writeHandshake(flight...); err != nil {
		return err
	}
	c.tracef("-> Finished")
	if err := c.out.setSecret(s, ks.clientAppTraffic); err != nil {
		return err
	}
	c.ccsAllowed = false

	c.state.Version = VersionTLS13
	c.state.CipherSuite = s.id
	c.state.Group = kx.group()
	c.state.ServerName = cfg.ServerName
	c.state.NegotiatedProto = ee.alpn
	return nil
}

// checkServerHello validates a ServerHello or HelloRetryRequest against
// what we offered.
func (c *Conn) checkServerHello(hello *clientHello, raw []byte) (*serverHello, error) {
	sh, err := parseServerHello(raw[4:])
	if err != nil {
		return nil, err
	}
	if sh.supportedVersion != VersionTLS13 {
		return nil, fail(alertProtocolVersion, "server does not support TLS 1.3")
	}
	if !bytes.Equal(sh.sessionID, hello.sessionID) {
		return nil, fail(alertIllegalParameter, "server did not echo the session ID")
	}
	if _, ok := suites[sh.cipherSuite]; !ok || !slices.Contains(hello.cipherSuites, sh.cipherSuite) {
		return nil, fail(alertIllegalParameter, "server chose unoffered cipher suite %v", sh.cipherSuite)
	}
	return sh, nil
}

func (c *Conn) verifyServerCertificates(chain [][]byte) error {
	cfg := c.config
	if len(chain) == 0 {
		return fail(alertDecodeError, "server sent no certificate")
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		cert, err := x509.Parse(der)
		if err != nil {
			return fail(alertBadCertificate, "certificate %d: %v", i, err)
		}
		certs[i] = cert
	}
	c.state.PeerCertificates = certs
	if certs[0].PublicKey == nil {
		return fail(alertUnsupportedCertificate, "unsupported public key in the server certificate")
	}
	if cfg.InsecureSkipVerify {
		c.tracef("<- Certificate: %s (verification skipped)", certs[0].Subject)
		return nil
	}
	roots := cfg.RootCAs
	if roots == nil {
		var err error
		if roots, err = SystemRoots(); err != nil {
			return fail(alertInternalError, "%v", err)
		}
	}
	verified, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: certs[1:],
		DNSName:       cfg.ServerName,
		CurrentTime:   cfg.now(),
	})
	if err != nil {
		a := alertBadCertificate
		if strings.Contains(err.Error(), "unknown authority") {
			a = alertUnknownCA
		} else if strings.Contains(err.Error(), "not valid at") {
			a = alertCertificateExpired
		}
		return fail(a, "%v", err)
	}
	c.state.VerifiedChain = verified
	names := make([]string, len(verified))
	for i, v := range verified {
		names[i] = v.Subject.CommonName
	}
	c.tracef("<- Certificate: chain verified: %s", strings.Join(names, " <- "))
	return nil
}
