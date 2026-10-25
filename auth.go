package handshake

import (
	"bytes"
	"errors"

	"github.com/pMag11-alt/handshake/internal/ecc"
	"github.com/pMag11-alt/handshake/internal/rsa"
	"github.com/pMag11-alt/handshake/internal/sha2"
	"github.com/pMag11-alt/handshake/internal/x509"
)

const (
	serverSignatureContext = "TLS 1.3, server CertificateVerify"
	clientSignatureContext = "TLS 1.3, client CertificateVerify"
)

// signedMessage is what CertificateVerify signs (RFC 8446 section 4.4.3):
// 64 spaces, a context string, a zero byte and the transcript hash. The
// padding defeats attacks that reuse TLS 1.2 signatures.
func signedMessage(context string, transcriptHash []byte) []byte {
	m := bytes.Repeat([]byte{0x20}, 64)
	m = append(m, context...)
	m = append(m, 0)
	return append(m, transcriptHash...)
}

// verifyCertificateVerify checks a server's signature over the transcript.
// PKCS #1 v1.5 schemes are not allowed here, only in certificates.
func verifyCertificateVerify(scheme SignatureScheme, pub any, msg, sig []byte) error {
	switch scheme {
	case ECDSAWithP256AndSHA256, ECDSAWithP384AndSHA384:
		key, ok := pub.(*ecc.PublicKey)
		if !ok {
			return errors.New("ECDSA scheme with a non-EC key")
		}
		curve, digest := ecc.P256, sha2.Sum256(msg)
		if scheme == ECDSAWithP384AndSHA384 {
			curve, digest = ecc.P384, sha2.Sum384(msg)
		}
		if key.Curve != curve {
			return errors.New("ECDSA scheme does not match the key's curve")
		}
		r, s, err := x509.ParseECDSASignature(sig)
		if err != nil {
			return err
		}
		if !ecc.Verify(key, digest, r, s) {
			return errors.New("ECDSA signature is invalid")
		}
		return nil
	case PSSWithSHA256, PSSWithSHA384, PSSWithSHA512:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errors.New("RSA-PSS scheme with a non-RSA key")
		}
		h, digest := pssHash(scheme, msg)
		return rsa.VerifyPSS(key, h, digest, sig)
	}
	return errors.New("signature scheme not allowed in TLS 1.3 CertificateVerify")
}

func pssHash(scheme SignatureScheme, msg []byte) (rsa.Hash, []byte) {
	switch scheme {
	case PSSWithSHA384:
		return rsa.SHA384, sha2.Sum384(msg)
	case PSSWithSHA512:
		return rsa.SHA512, sha2.Sum512(msg)
	}
	return rsa.SHA256, sha2.Sum256(msg)
}

// schemesFor lists what we can sign with a key, best first.
func schemesFor(priv any) []SignatureScheme {
	switch k := priv.(type) {
	case *ecc.PrivateKey:
		if k.Curve == ecc.P384 {
			return []SignatureScheme{ECDSAWithP384AndSHA384}
		}
		return []SignatureScheme{ECDSAWithP256AndSHA256}
	case *rsa.PrivateKey:
		return []SignatureScheme{PSSWithSHA256, PSSWithSHA384, PSSWithSHA512}
	}
	return nil
}

func signCertificateVerify(scheme SignatureScheme, priv any, msg []byte) ([]byte, error) {
	switch k := priv.(type) {
	case *ecc.PrivateKey:
		digest, h := sha2.Sum256(msg), sha2.New256
		if scheme == ECDSAWithP384AndSHA384 {
			digest, h = sha2.Sum384(msg), sha2.New384
		}
		r, s := ecc.Sign(k, digest, h)
		return x509.MarshalECDSASignature(r, s), nil
	case *rsa.PrivateKey:
		h, digest := pssHash(scheme, msg)
		return rsa.SignPSS(k, h, digest)
	}
	return nil, errors.New("unsupported private key")
}
