// Package x509 parses certificates (RFC 5280), builds and verifies chains
// to a set of trusted roots, and checks server host names.
package x509

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/pMag11-alt/handshake/internal/asn1"
	"github.com/pMag11-alt/handshake/internal/ecc"
	"github.com/pMag11-alt/handshake/internal/pem"
	"github.com/pMag11-alt/handshake/internal/rsa"
	"github.com/pMag11-alt/handshake/internal/sha2"
)

var (
	oidRSAEncryption   = asn1.OID{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.OID{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.OID{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.OID{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256 = asn1.OID{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.OID{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.OID{1, 2, 840, 10045, 4, 3, 4}
	oidECPublicKey     = asn1.OID{1, 2, 840, 10045, 2, 1}
	oidP256            = asn1.OID{1, 2, 840, 10045, 3, 1, 7}
	oidP384            = asn1.OID{1, 3, 132, 0, 34}

	oidCommonName   = asn1.OID{2, 5, 4, 3}
	oidOrganization = asn1.OID{2, 5, 4, 10}

	oidSubjectKeyID     = asn1.OID{2, 5, 29, 14}
	oidKeyUsage         = asn1.OID{2, 5, 29, 15}
	oidSubjectAltName   = asn1.OID{2, 5, 29, 17}
	oidBasicConstraints = asn1.OID{2, 5, 29, 19}
	oidAuthorityKeyID   = asn1.OID{2, 5, 29, 35}
	oidExtKeyUsage      = asn1.OID{2, 5, 29, 37}
	oidServerAuth       = asn1.OID{1, 3, 6, 1, 5, 5, 7, 3, 1}
	oidAnyExtKeyUsage   = asn1.OID{2, 5, 29, 37, 0}
)

// Key usage bits (RFC 5280 section 4.2.1.3).
const (
	KeyUsageDigitalSignature = 1 << 0
	KeyUsageCertSign         = 1 << 5
)

type SignatureAlgorithm int

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
)

func (a SignatureAlgorithm) String() string {
	return [...]string{"unknown", "SHA256-RSA", "SHA384-RSA", "SHA512-RSA", "ECDSA-SHA256", "ECDSA-SHA384", "ECDSA-SHA512"}[a]
}

// Name is a distinguished name. Chains are linked by comparing Raw bytes,
// which is what RFC 5280 path building does in practice.
type Name struct {
	Raw          []byte
	CommonName   string
	Organization string
}

func (n Name) String() string {
	parts := []string{}
	if n.CommonName != "" {
		parts = append(parts, "CN="+n.CommonName)
	}
	if n.Organization != "" {
		parts = append(parts, "O="+n.Organization)
	}
	return strings.Join(parts, ", ")
}

type Certificate struct {
	Raw                []byte
	RawTBS             []byte
	SerialNumber       *big.Int
	SignatureAlgorithm SignatureAlgorithm
	Signature          []byte
	Issuer, Subject    Name
	NotBefore          time.Time
	NotAfter           time.Time
	// PublicKey is *rsa.PublicKey or *ecc.PublicKey.
	PublicKey any

	DNSNames    []string
	IPAddresses []net.IP

	BasicConstraintsValid bool
	IsCA                  bool
	MaxPathLen            int // -1 when absent
	KeyUsage              int // 0 when the extension is absent
	ExtKeyUsage           []asn1.OID
	SubjectKeyID          []byte
	AuthorityKeyID        []byte
}

func parseAlgorithm(r *asn1.Reader) (asn1.OID, asn1.Element, error) {
	seq, err := r.Sequence()
	if err != nil {
		return nil, asn1.Element{}, err
	}
	oid, err := seq.OID()
	if err != nil {
		return nil, asn1.Element{}, err
	}
	var params asn1.Element
	if !seq.Empty() {
		params, err = seq.Read()
	}
	return oid, params, err
}

func signatureAlgorithm(oid asn1.OID) SignatureAlgorithm {
	switch {
	case oid.Equal(oidSHA256WithRSA):
		return SHA256WithRSA
	case oid.Equal(oidSHA384WithRSA):
		return SHA384WithRSA
	case oid.Equal(oidSHA512WithRSA):
		return SHA512WithRSA
	case oid.Equal(oidECDSAWithSHA256):
		return ECDSAWithSHA256
	case oid.Equal(oidECDSAWithSHA384):
		return ECDSAWithSHA384
	case oid.Equal(oidECDSAWithSHA512):
		return ECDSAWithSHA512
	}
	return UnknownSignatureAlgorithm
}

func parseName(e asn1.Element) (Name, error) {
	n := Name{Raw: e.Raw}
	rdns := asn1.NewReader(e.Contents)
	for !rdns.Empty() {
		set, err := rdns.Expect(asn1.TagSet)
		if err != nil {
			return n, err
		}
		attrs := asn1.NewReader(set.Contents)
		for !attrs.Empty() {
			atv, err := attrs.Sequence()
			if err != nil {
				return n, err
			}
			oid, err := atv.OID()
			if err != nil {
				return n, err
			}
			value, err := atv.Read()
			if err != nil {
				return n, err
			}
			s, err := asn1.String(value)
			if err != nil {
				continue // attribute types we don't display
			}
			switch {
			case oid.Equal(oidCommonName):
				n.CommonName = s
			case oid.Equal(oidOrganization):
				n.Organization = s
			}
		}
	}
	return n, nil
}

// ParsePublicKeyInfo decodes a SubjectPublicKeyInfo.
func ParsePublicKeyInfo(der []byte) (any, error) {
	r := asn1.NewReader(der)
	spki, err := r.Sequence()
	if err != nil {
		return nil, err
	}
	alg, params, err := parseAlgorithm(spki)
	if err != nil {
		return nil, err
	}
	key, err := spki.BitString()
	if err != nil {
		return nil, err
	}
	switch {
	case alg.Equal(oidRSAEncryption):
		seq, err := asn1.NewReader(key).Sequence()
		if err != nil {
			return nil, err
		}
		n, err := seq.BigInt()
		if err != nil {
			return nil, err
		}
		e, err := seq.Int()
		if err != nil {
			return nil, err
		}
		if n.Sign() <= 0 || e < 3 || e%2 == 0 {
			return nil, errors.New("x509: invalid RSA public key")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case alg.Equal(oidECPublicKey):
		if params.Tag != asn1.TagOID {
			return nil, errors.New("x509: EC key without a named curve")
		}
		curveOID, err := asn1.ParseOID(params.Contents)
		if err != nil {
			return nil, err
		}
		curve := curveFromOID(curveOID)
		if curve == nil {
			return nil, fmt.Errorf("x509: unsupported curve %v", curveOID)
		}
		pub, err := ecc.ParsePublicKey(curve, key)
		if err != nil {
			// Return a plain nil: a nil *ecc.PublicKey inside an interface
			// would compare non-nil and slip past checks.
			return nil, err
		}
		return pub, nil
	}
	return nil, fmt.Errorf("x509: unsupported public key algorithm %v", alg)
}

func curveFromOID(oid asn1.OID) *ecc.Curve {
	switch {
	case oid.Equal(oidP256):
		return ecc.P256
	case oid.Equal(oidP384):
		return ecc.P384
	}
	return nil
}

// Parse decodes a DER certificate.
func Parse(der []byte) (*Certificate, error) {
	c := &Certificate{Raw: der, MaxPathLen: -1}
	outer := asn1.NewReader(der)
	cert, err := outer.Sequence()
	if err != nil {
		return nil, err
	}
	if !outer.Empty() {
		return nil, errors.New("x509: trailing data after certificate")
	}
	tbsEl, err := cert.Expect(asn1.TagSequence)
	if err != nil {
		return nil, err
	}
	c.RawTBS = tbsEl.Raw
	sigAlg, _, err := parseAlgorithm(cert)
	if err != nil {
		return nil, err
	}
	c.SignatureAlgorithm = signatureAlgorithm(sigAlg)
	if c.Signature, err = cert.BitString(); err != nil {
		return nil, err
	}

	tbs := asn1.NewReader(tbsEl.Contents)
	version := 0
	if v, ok, err := tbs.Optional(asn1.ContextSpecific(0, true)); err != nil {
		return nil, err
	} else if ok {
		if version, err = asn1.NewReader(v.Contents).Int(); err != nil {
			return nil, err
		}
	}
	if c.SerialNumber, err = tbs.BigInt(); err != nil {
		return nil, err
	}
	innerAlg, _, err := parseAlgorithm(tbs)
	if err != nil {
		return nil, err
	}
	if !innerAlg.Equal(sigAlg) {
		return nil, errors.New("x509: signature algorithms disagree")
	}
	issuer, err := tbs.Expect(asn1.TagSequence)
	if err != nil {
		return nil, err
	}
	if c.Issuer, err = parseName(issuer); err != nil {
		return nil, err
	}
	validity, err := tbs.Sequence()
	if err != nil {
		return nil, err
	}
	if c.NotBefore, err = validity.Time(); err != nil {
		return nil, err
	}
	if c.NotAfter, err = validity.Time(); err != nil {
		return nil, err
	}
	subject, err := tbs.Expect(asn1.TagSequence)
	if err != nil {
		return nil, err
	}
	if c.Subject, err = parseName(subject); err != nil {
		return nil, err
	}
	spki, err := tbs.Expect(asn1.TagSequence)
	if err != nil {
		return nil, err
	}
	// Keep going with an unsupported key type: such a certificate can still
	// be a trust anchor we never need to verify with.
	if pub, err := ParsePublicKeyInfo(spki.Raw); err == nil {
		c.PublicKey = pub
	}

	for !tbs.Empty() {
		e, err := tbs.Read()
		if err != nil {
			return nil, err
		}
		if e.Tag == asn1.ContextSpecific(3, true) && version == 2 {
			if err := c.parseExtensions(e.Contents); err != nil {
				return nil, err
			}
		}
	}
	return c, nil
}

func (c *Certificate) parseExtensions(data []byte) error {
	exts, err := asn1.NewReader(data).Sequence()
	if err != nil {
		return err
	}
	for !exts.Empty() {
		ext, err := exts.Sequence()
		if err != nil {
			return err
		}
		oid, err := ext.OID()
		if err != nil {
			return err
		}
		critical := false
		if ext.PeekTag() == asn1.TagBoolean {
			if critical, err = ext.Bool(); err != nil {
				return err
			}
		}
		value, err := ext.OctetString()
		if err != nil {
			return err
		}
		v := asn1.NewReader(value)
		switch {
		case oid.Equal(oidSubjectAltName):
			names, err := v.Sequence()
			if err != nil {
				return err
			}
			for !names.Empty() {
				gn, err := names.Read()
				if err != nil {
					return err
				}
				switch gn.Tag {
				case asn1.ContextSpecific(2, false):
					c.DNSNames = append(c.DNSNames, string(gn.Contents))
				case asn1.ContextSpecific(7, false):
					if len(gn.Contents) == 4 || len(gn.Contents) == 16 {
						c.IPAddresses = append(c.IPAddresses, net.IP(gn.Contents))
					}
				}
			}
		case oid.Equal(oidBasicConstraints):
			seq, err := v.Sequence()
			if err != nil {
				return err
			}
			c.BasicConstraintsValid = true
			if seq.PeekTag() == asn1.TagBoolean {
				if c.IsCA, err = seq.Bool(); err != nil {
					return err
				}
			}
			if seq.PeekTag() == asn1.TagInteger {
				if c.MaxPathLen, err = seq.Int(); err != nil {
					return err
				}
			}
		case oid.Equal(oidKeyUsage):
			e, err := v.Expect(asn1.TagBitString)
			if err != nil {
				return err
			}
			if c.KeyUsage, err = asn1.BitStringFlags(e.Contents); err != nil {
				return err
			}
		case oid.Equal(oidExtKeyUsage):
			seq, err := v.Sequence()
			if err != nil {
				return err
			}
			for !seq.Empty() {
				o, err := seq.OID()
				if err != nil {
					return err
				}
				c.ExtKeyUsage = append(c.ExtKeyUsage, o)
			}
		case oid.Equal(oidSubjectKeyID):
			if c.SubjectKeyID, err = v.OctetString(); err != nil {
				return err
			}
		case oid.Equal(oidAuthorityKeyID):
			seq, err := v.Sequence()
			if err != nil {
				return err
			}
			if e, ok, _ := seq.Optional(asn1.ContextSpecific(0, false)); ok {
				c.AuthorityKeyID = e.Contents
			}
		default:
			if critical {
				// Name constraints, policy constraints and friends: fail
				// closed rather than ignore something the issuer requires.
				return fmt.Errorf("x509: unhandled critical extension %v", oid)
			}
		}
	}
	return nil
}

// CheckSignature verifies a signature made by this certificate's key.
func CheckSignature(alg SignatureAlgorithm, pub any, signed, sig []byte) error {
	var digest []byte
	var rsaHash rsa.Hash
	switch alg {
	case SHA256WithRSA, ECDSAWithSHA256:
		digest, rsaHash = sha2.Sum256(signed), rsa.SHA256
	case SHA384WithRSA, ECDSAWithSHA384:
		digest, rsaHash = sha2.Sum384(signed), rsa.SHA384
	case SHA512WithRSA, ECDSAWithSHA512:
		digest, rsaHash = sha2.Sum512(signed), rsa.SHA512
	default:
		return errors.New("x509: unsupported signature algorithm")
	}
	switch key := pub.(type) {
	case *rsa.PublicKey:
		if key == nil {
			return errors.New("x509: missing public key")
		}
		if alg != SHA256WithRSA && alg != SHA384WithRSA && alg != SHA512WithRSA {
			return errors.New("x509: signature algorithm does not match an RSA key")
		}
		return rsa.VerifyPKCS1v15(key, rsaHash, digest, sig)
	case *ecc.PublicKey:
		if key == nil {
			return errors.New("x509: missing public key")
		}
		if alg != ECDSAWithSHA256 && alg != ECDSAWithSHA384 && alg != ECDSAWithSHA512 {
			return errors.New("x509: signature algorithm does not match an EC key")
		}
		r, s, err := ParseECDSASignature(sig)
		if err != nil {
			return err
		}
		if !ecc.Verify(key, digest, r, s) {
			return errors.New("x509: ECDSA verification failure")
		}
		return nil
	}
	return errors.New("x509: unsupported public key")
}

// ParseECDSASignature decodes SEQUENCE { r INTEGER, s INTEGER }.
func ParseECDSASignature(sig []byte) (*big.Int, *big.Int, error) {
	outer := asn1.NewReader(sig)
	seq, err := outer.Sequence()
	if err != nil || !outer.Empty() {
		return nil, nil, errors.New("x509: malformed ECDSA signature")
	}
	r, err := seq.BigInt()
	if err != nil {
		return nil, nil, err
	}
	s, err := seq.BigInt()
	if err != nil || !seq.Empty() {
		return nil, nil, errors.New("x509: malformed ECDSA signature")
	}
	return r, s, nil
}

// MarshalECDSASignature encodes (r, s) for TLS and certificates.
func MarshalECDSASignature(r, s *big.Int) []byte {
	return asn1.Sequence(asn1.Integer(r), asn1.Integer(s))
}

// CheckSignatureFrom verifies that parent signed c.
func (c *Certificate) CheckSignatureFrom(parent *Certificate) error {
	return CheckSignature(c.SignatureAlgorithm, parent.PublicKey, c.RawTBS, c.Signature)
}

// ---- trust and verification ------------------------------------------------------

// Pool is a set of trusted root certificates.
type Pool struct {
	bySubject map[string][]*Certificate
	count     int
}

func NewPool() *Pool { return &Pool{bySubject: map[string][]*Certificate{}} }

func (p *Pool) Add(c *Certificate) {
	key := string(c.Subject.Raw)
	for _, existing := range p.bySubject[key] {
		if bytes.Equal(existing.Raw, c.Raw) {
			return
		}
	}
	p.bySubject[key] = append(p.bySubject[key], c)
	p.count++
}

// AddPEM adds every certificate in a PEM bundle and returns how many parsed.
func (p *Pool) AddPEM(data []byte) int {
	n := 0
	for _, b := range pem.Decode(data) {
		if b.Type != "CERTIFICATE" {
			continue
		}
		if c, err := Parse(b.Bytes); err == nil {
			p.Add(c)
			n++
		}
	}
	return n
}

func (p *Pool) Len() int { return p.count }

func (p *Pool) contains(c *Certificate) bool {
	for _, r := range p.bySubject[string(c.Subject.Raw)] {
		if bytes.Equal(r.Raw, c.Raw) {
			return true
		}
	}
	return false
}

type VerifyOptions struct {
	Roots         *Pool
	Intermediates []*Certificate
	DNSName       string
	CurrentTime   time.Time
}

// VerificationError explains why no chain to a trusted root was found.
type VerificationError struct{ Reason string }

func (e *VerificationError) Error() string { return "x509: " + e.Reason }

const maxChainLength = 8

// Verify builds a chain from leaf to a trusted root, checking signatures,
// validity periods and CA constraints along the way, then the host name.
func (leaf *Certificate) Verify(opts VerifyOptions) ([]*Certificate, error) {
	now := opts.CurrentTime
	if now.IsZero() {
		now = time.Now()
	}
	if opts.DNSName != "" {
		if err := leaf.VerifyHostname(opts.DNSName); err != nil {
			return nil, err
		}
	}
	if len(leaf.ExtKeyUsage) > 0 && !hasEKU(leaf, oidServerAuth) {
		return nil, &VerificationError{"leaf certificate is not valid for server authentication"}
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, &VerificationError{fmt.Sprintf("certificate %q is not valid at %s", leaf.Subject, now.Format(time.RFC3339))}
	}
	// rejected remembers why the last candidate issuer was turned down, to
	// explain an otherwise bare "unknown authority".
	var rejected string
	var search func(chain []*Certificate) []*Certificate
	search = func(chain []*Certificate) []*Certificate {
		cur := chain[len(chain)-1]
		if now.Before(cur.NotBefore) || now.After(cur.NotAfter) {
			rejected = fmt.Sprintf("%q is not valid at %s", cur.Subject, now.Format(time.RFC3339))
			return nil
		}
		if opts.Roots.contains(cur) {
			return chain
		}
		if len(chain) == maxChainLength {
			return nil
		}
		// Prefer trust anchors over intermediates with the same subject, so
		// an expired cross-sign is never needed when a root is present.
		candidates := append([]*Certificate{}, opts.Roots.bySubject[string(cur.Issuer.Raw)]...)
		for _, ic := range opts.Intermediates {
			if bytes.Equal(ic.Subject.Raw, cur.Issuer.Raw) {
				candidates = append(candidates, ic)
			}
		}
		for _, parent := range candidates {
			if inChain(chain, parent) {
				continue
			}
			if len(cur.AuthorityKeyID) > 0 && len(parent.SubjectKeyID) > 0 && !bytes.Equal(cur.AuthorityKeyID, parent.SubjectKeyID) {
				continue
			}
			if err := checkIssuer(parent, len(chain)-1); err != nil {
				rejected = err.Error()
				continue
			}
			if err := cur.CheckSignatureFrom(parent); err != nil {
				rejected = fmt.Sprintf("bad signature on %q from %q: %v", cur.Subject, parent.Subject, err)
				continue
			}
			if found := search(append(chain[:len(chain):len(chain)], parent)); found != nil {
				return found
			}
		}
		return nil
	}
	if chain := search([]*Certificate{leaf}); chain != nil {
		return chain, nil
	}
	reason := "certificate signed by unknown authority"
	if rejected != "" {
		reason += " (" + strings.TrimPrefix(rejected, "x509: ") + ")"
	}
	return nil, &VerificationError{reason}
}

func inChain(chain []*Certificate, c *Certificate) bool {
	for _, x := range chain {
		if bytes.Equal(x.Raw, c.Raw) {
			return true
		}
	}
	return false
}

// checkIssuer enforces basicConstraints, path length and keyUsage for a
// certificate used to sign others; below counts the intermediate CAs
// between it and the leaf.
func checkIssuer(c *Certificate, below int) error {
	if !c.BasicConstraintsValid || !c.IsCA {
		return &VerificationError{fmt.Sprintf("%q is not a CA", c.Subject)}
	}
	if c.KeyUsage != 0 && c.KeyUsage&KeyUsageCertSign == 0 {
		return &VerificationError{fmt.Sprintf("%q may not sign certificates", c.Subject)}
	}
	if c.MaxPathLen >= 0 && below > c.MaxPathLen {
		return &VerificationError{fmt.Sprintf("path length constraint of %q exceeded", c.Subject)}
	}
	return nil
}

func hasEKU(c *Certificate, want asn1.OID) bool {
	for _, o := range c.ExtKeyUsage {
		if o.Equal(want) || o.Equal(oidAnyExtKeyUsage) {
			return true
		}
	}
	return false
}

// VerifyHostname checks host against the subjectAltName extension. The
// legacy fallback to the subject's common name is not supported.
func (c *Certificate) VerifyHostname(host string) error {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		for _, candidate := range c.IPAddresses {
			if candidate.Equal(ip) {
				return nil
			}
		}
		return &VerificationError{fmt.Sprintf("certificate is not valid for IP address %s", host)}
	}
	for _, name := range c.DNSNames {
		if matchHostname(strings.ToLower(name), host) {
			return nil
		}
	}
	return &VerificationError{fmt.Sprintf("certificate is valid for %s, not %s", strings.Join(c.DNSNames, ", "), host)}
}

// matchHostname supports a wildcard only as the entire left-most label.
func matchHostname(pattern, host string) bool {
	pattern = strings.TrimSuffix(pattern, ".")
	if pattern == host {
		return true
	}
	if !strings.HasPrefix(pattern, "*.") {
		return false
	}
	dot := strings.IndexByte(host, '.')
	if dot <= 0 {
		return false
	}
	suffix := pattern[1:]
	return host[dot:] == suffix && strings.Count(suffix, ".") >= 2
}
