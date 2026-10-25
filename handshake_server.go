package handshake

import (
	"errors"
	"io"
	"slices"

	"github.com/pMag11-alt/handshake/internal/hmac"
)

func (c *Conn) serverHandshake() error {
	cfg := c.config
	if cfg == nil || cfg.Certificate == nil || len(cfg.Certificate.Chain) == 0 {
		return errors.New("tls: server needs Config.Certificate")
	}
	rand := cfg.rand()

	_, chRaw, err := c.expect(typeClientHello, nil)
	if err != nil {
		return err
	}
	ch, err := parseClientHello(chRaw[4:])
	if err != nil {
		return err
	}
	c.clientRandom = ch.random
	if !slices.Contains(ch.supportedVersions, VersionTLS13) {
		return fail(alertProtocolVersion, "client does not offer TLS 1.3")
	}
	c.tracef("<- ClientHello: SNI=%q suites=%v groups=%v", ch.serverName, ch.cipherSuites, ch.supportedGroups)

	// Our preference order decides the suite and group.
	var s *suite
	for _, id := range cfg.cipherSuites() {
		if slices.Contains(ch.cipherSuites, id) {
			s = suites[id]
			break
		}
	}
	if s == nil {
		return fail(alertHandshakeFailure, "no cipher suite in common")
	}
	scheme, err := pickScheme(cfg.Certificate.PrivateKey, ch.signatureSchemes)
	if err != nil {
		return err
	}
	var alpn string
	if len(ch.alpn) > 0 && len(cfg.NextProtos) > 0 {
		for _, p := range cfg.NextProtos {
			if slices.Contains(ch.alpn, p) {
				alpn = p
				break
			}
		}
		if alpn == "" {
			return fail(alertNoApplicationProtocol, "no protocol in common for ALPN")
		}
	}
	if !ch.keyShareSeen || len(ch.supportedGroups) == 0 {
		return fail(alertMissingExtension, "ClientHello without key_share or supported_groups")
	}

	group, clientShare := chooseGroup(cfg.curves(), ch)
	transcript := s.newHash()
	transcript.Write(chRaw)
	sentCCS := false

	if clientShare == nil {
		// No usable key share: ask for one with a HelloRetryRequest.
		if group == 0 {
			return fail(alertHandshakeFailure, "no key exchange group in common")
		}
		digest := s.newHash()
		digest.Write(chRaw)
		sum := digest.Sum(nil)
		transcript = s.newHash()
		transcript.Write([]byte{typeMessageHash, 0, 0, byte(len(sum))})
		transcript.Write(sum)
		hrr := (&serverHello{
			random:           hrrRandom,
			sessionID:        ch.sessionID,
			cipherSuite:      s.id,
			supportedVersion: VersionTLS13,
			selectedGroup:    group,
		}).marshal()
		transcript.Write(hrr)
		if err := c.writeHandshake(hrr); err != nil {
			return err
		}
		c.tracef("-> HelloRetryRequest: send a %v key share", group)
		if len(ch.sessionID) > 0 {
			if err := c.writeRecord(recordChangeCipherSpec, []byte{1}); err != nil {
				return err
			}
			sentCCS = true
		}
		c.ccsAllowed = true
		_, ch2Raw, err := c.expect(typeClientHello, nil)
		if err != nil {
			return err
		}
		ch2, err := parseClientHello(ch2Raw[4:])
		if err != nil {
			return err
		}
		if len(ch2.keyShares) != 1 || ch2.keyShares[0].group != group || !slices.Contains(ch2.cipherSuites, s.id) {
			return fail(alertIllegalParameter, "second ClientHello does not follow the HelloRetryRequest")
		}
		transcript.Write(ch2Raw)
		ch, clientShare = ch2, ch2.keyShares[0].data
		c.state.HelloRetried = true
	}

	kx, err := newKeyExchange(group, rand)
	if err != nil {
		return err
	}
	shared, err := kx.shared(clientShare)
	if err != nil {
		return fail(alertIllegalParameter, "bad client key share: %v", err)
	}
	sh := &serverHello{
		random:           make([]byte, 32),
		sessionID:        ch.sessionID,
		cipherSuite:      s.id,
		supportedVersion: VersionTLS13,
		keyShare:         keyShare{group, kx.public()},
	}
	if _, err := io.ReadFull(rand, sh.random); err != nil {
		return err
	}
	shRaw := sh.marshal()
	transcript.Write(shRaw)
	if err := c.writeHandshake(shRaw); err != nil {
		return err
	}
	if !sentCCS && len(ch.sessionID) > 0 {
		if err := c.writeRecord(recordChangeCipherSpec, []byte{1}); err != nil {
			return err
		}
	}
	c.tracef("-> ServerHello: %v, %v", s.id, group)

	ks := &schedule{suite: s}
	ks.handshake(shared, transcript)
	c.keyLog("CLIENT_HANDSHAKE_TRAFFIC_SECRET", ks.clientHandshakeTraffic)
	c.keyLog("SERVER_HANDSHAKE_TRAFFIC_SECRET", ks.serverHandshakeTraffic)
	if err := c.out.setSecret(s, ks.serverHandshakeTraffic); err != nil {
		return err
	}
	if err := c.setReadSecret(s, ks.clientHandshakeTraffic); err != nil {
		return err
	}
	c.ccsAllowed = true

	ee := (&encryptedExtensions{alpn: alpn}).marshal()
	transcript.Write(ee)
	certMsg := (&certificateMsg{chain: cfg.Certificate.Chain}).marshal()
	transcript.Write(certMsg)
	sig, err := signCertificateVerify(scheme, cfg.Certificate.PrivateKey, signedMessage(serverSignatureContext, transcript.Sum(nil)))
	if err != nil {
		return fail(alertInternalError, "signing CertificateVerify: %v", err)
	}
	cv := (&certificateVerifyMsg{scheme: scheme, signature: sig}).marshal()
	transcript.Write(cv)
	fin := marshalFinished(s.finished(ks.serverHandshakeTraffic, transcript))
	transcript.Write(fin)
	if err := c.writeHandshake(ee, certMsg, cv, fin); err != nil {
		return err
	}
	c.tracef("-> EncryptedExtensions, Certificate, CertificateVerify (%v), Finished", scheme)

	// The client's Finished covers the transcript through our Finished.
	expected := s.finished(ks.clientHandshakeTraffic, transcript)
	ks.application(transcript)
	c.keyLog("CLIENT_TRAFFIC_SECRET_0", ks.clientAppTraffic)
	c.keyLog("SERVER_TRAFFIC_SECRET_0", ks.serverAppTraffic)
	c.keyLog("EXPORTER_SECRET", ks.exporterMaster)
	if err := c.out.setSecret(s, ks.serverAppTraffic); err != nil {
		return err
	}

	typ, body, _, err := c.readHandshake()
	if err != nil {
		return err
	}
	if typ == typeCertificate {
		return fail(alertUnexpectedMessage, "client certificates were not requested")
	}
	if typ != typeFinished {
		return fail(alertUnexpectedMessage, "expected Finished, got message %d", typ)
	}
	if !hmac.Equal(body, expected) {
		return fail(alertDecryptError, "client Finished does not match the transcript")
	}
	c.tracef("<- Finished: client's transcript MAC matches")
	if err := c.setReadSecret(s, ks.clientAppTraffic); err != nil {
		return err
	}
	c.ccsAllowed = false

	c.state.Version = VersionTLS13
	c.state.CipherSuite = s.id
	c.state.Group = group
	c.state.SignatureScheme = scheme
	c.state.ServerName = ch.serverName
	c.state.NegotiatedProto = alpn
	return nil
}

// chooseGroup picks our most preferred group the client sent a share
// for; failing that, the most preferred group it supports (for a
// HelloRetryRequest), returning a nil share.
func chooseGroup(ours []CurveID, ch *clientHello) (CurveID, []byte) {
	for _, g := range ours {
		for _, ks := range ch.keyShares {
			if ks.group == g {
				return g, ks.data
			}
		}
	}
	for _, g := range ours {
		if slices.Contains(ch.supportedGroups, g) {
			return g, nil
		}
	}
	return 0, nil
}

func pickScheme(priv any, offered []SignatureScheme) (SignatureScheme, error) {
	for _, s := range schemesFor(priv) {
		if slices.Contains(offered, s) {
			return s, nil
		}
	}
	return 0, fail(alertHandshakeFailure, "client accepts no signature scheme our key can produce")
}
