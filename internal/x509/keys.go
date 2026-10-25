package x509

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"github.com/pMag11-alt/handshake/internal/asn1"
	"github.com/pMag11-alt/handshake/internal/ecc"
	"github.com/pMag11-alt/handshake/internal/pem"
	"github.com/pMag11-alt/handshake/internal/rsa"
	"github.com/pMag11-alt/handshake/internal/sha2"
)

func curveOID(c *ecc.Curve) asn1.OID {
	if c == ecc.P384 {
		return oidP384
	}
	return oidP256
}

// MarshalPublicKeyInfo encodes a SubjectPublicKeyInfo.
func MarshalPublicKeyInfo(pub any) ([]byte, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		body := asn1.Sequence(asn1.Integer(k.N), asn1.SmallInt(k.E))
		return asn1.Sequence(
			asn1.Sequence(asn1.ObjectIdentifier(oidRSAEncryption), asn1.Null()),
			asn1.BitString(body),
		), nil
	case *ecc.PublicKey:
		return asn1.Sequence(
			asn1.Sequence(asn1.ObjectIdentifier(oidECPublicKey), asn1.ObjectIdentifier(curveOID(k.Curve))),
			asn1.BitString(k.Bytes()),
		), nil
	}
	return nil, errors.New("x509: unsupported key type")
}

// MarshalPKCS8 encodes a private key as PKCS #8 PrivateKeyInfo.
func MarshalPKCS8(priv any) ([]byte, error) {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		inner := asn1.Sequence(asn1.SmallInt(0), asn1.Integer(k.N), asn1.SmallInt(k.E), asn1.Integer(k.D),
			asn1.Integer(k.P), asn1.Integer(k.Q), asn1.Integer(k.Dp), asn1.Integer(k.Dq), asn1.Integer(k.QInv))
		return asn1.Sequence(asn1.SmallInt(0),
			asn1.Sequence(asn1.ObjectIdentifier(oidRSAEncryption), asn1.Null()),
			asn1.OctetString(inner)), nil
	case *ecc.PrivateKey:
		d := k.D.FillBytes(make([]byte, k.Curve.Bytes))
		inner := asn1.Sequence(asn1.SmallInt(1), asn1.OctetString(d), asn1.Explicit(1, asn1.BitString(k.PublicKey.Bytes())))
		return asn1.Sequence(asn1.SmallInt(0),
			asn1.Sequence(asn1.ObjectIdentifier(oidECPublicKey), asn1.ObjectIdentifier(curveOID(k.Curve))),
			asn1.OctetString(inner)), nil
	}
	return nil, errors.New("x509: unsupported key type")
}

// ParsePrivateKeyPEM accepts PKCS #8 ("PRIVATE KEY"), PKCS #1 ("RSA PRIVATE
// KEY") and SEC 1 ("EC PRIVATE KEY") blocks.
func ParsePrivateKeyPEM(data []byte) (any, error) {
	for _, b := range pem.Decode(data) {
		switch b.Type {
		case "PRIVATE KEY":
			return parsePKCS8(b.Bytes)
		case "RSA PRIVATE KEY":
			return parsePKCS1(b.Bytes)
		case "EC PRIVATE KEY":
			return parseSEC1(b.Bytes, nil)
		}
	}
	return nil, errors.New("x509: no private key found")
}

func parsePKCS8(der []byte) (any, error) {
	seq, err := asn1.NewReader(der).Sequence()
	if err != nil {
		return nil, err
	}
	if _, err := seq.Int(); err != nil {
		return nil, err
	}
	alg, params, err := parseAlgorithm(seq)
	if err != nil {
		return nil, err
	}
	inner, err := seq.OctetString()
	if err != nil {
		return nil, err
	}
	switch {
	case alg.Equal(oidRSAEncryption):
		return parsePKCS1(inner)
	case alg.Equal(oidECPublicKey):
		oid, err := asn1.ParseOID(params.Contents)
		if err != nil {
			return nil, err
		}
		return parseSEC1(inner, curveFromOID(oid))
	}
	return nil, fmt.Errorf("x509: unsupported private key algorithm %v", alg)
}

func parsePKCS1(der []byte) (*rsa.PrivateKey, error) {
	seq, err := asn1.NewReader(der).Sequence()
	if err != nil {
		return nil, err
	}
	if _, err := seq.Int(); err != nil {
		return nil, err
	}
	var v [8]*big.Int
	for i := range v {
		if v[i], err = seq.BigInt(); err != nil {
			return nil, err
		}
	}
	k := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: v[0], E: int(v[1].Int64())},
		D:         v[2], P: v[3], Q: v[4], Dp: v[5], Dq: v[6], QInv: v[7],
	}
	if new(big.Int).Mul(k.P, k.Q).Cmp(k.N) != 0 {
		return nil, errors.New("x509: inconsistent RSA key")
	}
	return k, nil
}

func parseSEC1(der []byte, curve *ecc.Curve) (*ecc.PrivateKey, error) {
	seq, err := asn1.NewReader(der).Sequence()
	if err != nil {
		return nil, err
	}
	if _, err := seq.Int(); err != nil {
		return nil, err
	}
	d, err := seq.OctetString()
	if err != nil {
		return nil, err
	}
	if e, ok, _ := seq.Optional(asn1.ContextSpecific(0, true)); ok {
		oid, err := asn1.NewReader(e.Contents).OID()
		if err != nil {
			return nil, err
		}
		curve = curveFromOID(oid)
	}
	if curve == nil {
		return nil, errors.New("x509: unsupported or missing EC curve")
	}
	return ecc.NewPrivateKey(curve, new(big.Int).SetBytes(d)), nil
}

// Template describes a certificate to create.
type Template struct {
	CommonName string
	DNSNames   []string
	IPs        []net.IP
	NotBefore  time.Time
	NotAfter   time.Time
	IsCA       bool
}

// CreateSelfSigned issues a certificate for priv's public key, signed by
// priv itself.
func CreateSelfSigned(t Template, priv any) ([]byte, error) {
	var pub any
	var sigAlg asn1.OID
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		pub, sigAlg = &k.PublicKey, oidSHA256WithRSA
	case *ecc.PrivateKey:
		pub, sigAlg = &k.PublicKey, oidECDSAWithSHA256
		if k.Curve == ecc.P384 {
			sigAlg = oidECDSAWithSHA384
		}
	default:
		return nil, errors.New("x509: unsupported key type")
	}
	spki, err := MarshalPublicKeyInfo(pub)
	if err != nil {
		return nil, err
	}
	serialBytes := make([]byte, 16)
	if _, err := rand.Read(serialBytes); err != nil {
		return nil, err
	}
	serialBytes[0] &= 0x7f
	serial := new(big.Int).SetBytes(serialBytes)

	name := asn1.Sequence(asn1.Set(asn1.Sequence(asn1.ObjectIdentifier(oidCommonName), asn1.UTF8String(t.CommonName))))
	var sans [][]byte
	for _, d := range t.DNSNames {
		sans = append(sans, asn1.TLV(asn1.ContextSpecific(2, false), []byte(d)))
	}
	for _, ip := range t.IPs {
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		sans = append(sans, asn1.TLV(asn1.ContextSpecific(7, false), ip))
	}
	usage := byte(0x80) // digitalSignature
	if t.IsCA {
		usage |= 0x04 // keyCertSign
	}
	skid := sha2.Sum256(spki)[:20]
	exts := [][]byte{
		extension(oidKeyUsage, true, asn1.TLV(asn1.TagBitString, []byte{0, usage})),
		extension(oidBasicConstraints, true, asn1.Sequence(boolIf(t.IsCA))),
		extension(oidSubjectKeyID, false, asn1.OctetString(skid)),
	}
	if !t.IsCA {
		exts = append(exts, extension(oidExtKeyUsage, false, asn1.Sequence(asn1.ObjectIdentifier(oidServerAuth))))
	}
	if len(sans) > 0 {
		exts = append(exts, extension(oidSubjectAltName, false, asn1.Sequence(sans...)))
	}
	algID := asn1.Sequence(asn1.ObjectIdentifier(sigAlg))
	if sigAlg.Equal(oidSHA256WithRSA) {
		algID = asn1.Sequence(asn1.ObjectIdentifier(sigAlg), asn1.Null())
	}
	tbs := asn1.Sequence(
		asn1.Explicit(0, asn1.SmallInt(2)),
		asn1.Integer(serial),
		algID,
		name,
		asn1.Sequence(asn1.UTCTimeOrGeneralized(t.NotBefore), asn1.UTCTimeOrGeneralized(t.NotAfter)),
		name,
		spki,
		asn1.Explicit(3, asn1.Sequence(exts...)),
	)

	var sig []byte
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		if sig, err = rsa.SignPKCS1v15(k, rsa.SHA256, sha2.Sum256(tbs)); err != nil {
			return nil, err
		}
	case *ecc.PrivateKey:
		digest, h := sha2.Sum256(tbs), sha2.New256
		if k.Curve == ecc.P384 {
			digest, h = sha2.Sum384(tbs), sha2.New384
		}
		r, s := ecc.Sign(k, digest, h)
		sig = MarshalECDSASignature(r, s)
	}
	return asn1.Sequence(tbs, algID, asn1.BitString(sig)), nil
}

func boolIf(ca bool) []byte {
	if ca {
		return asn1.Boolean(true)
	}
	return nil
}

func extension(oid asn1.OID, critical bool, value []byte) []byte {
	if critical {
		return asn1.Sequence(asn1.ObjectIdentifier(oid), asn1.Boolean(true), asn1.OctetString(value))
	}
	return asn1.Sequence(asn1.ObjectIdentifier(oid), asn1.OctetString(value))
}
