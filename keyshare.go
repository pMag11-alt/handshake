package handshake

import (
	"errors"
	"io"
	"math/big"

	"github.com/pMag11-alt/handshake/internal/ecc"
	"github.com/pMag11-alt/handshake/internal/x25519"
)

// keyExchange is an ephemeral (EC)DHE key pair for one group.
type keyExchange interface {
	group() CurveID
	public() []byte
	shared(peer []byte) ([]byte, error)
}

type x25519Exchange struct{ priv, pub []byte }

func (k *x25519Exchange) group() CurveID { return X25519 }
func (k *x25519Exchange) public() []byte { return k.pub }
func (k *x25519Exchange) shared(peer []byte) ([]byte, error) {
	if len(peer) != x25519.PointSize {
		return nil, errors.New("bad X25519 key share")
	}
	return x25519.X25519(k.priv, peer)
}

type nistExchange struct {
	id   CurveID
	priv *ecc.PrivateKey
}

func (k *nistExchange) group() CurveID { return k.id }
func (k *nistExchange) public() []byte { return k.priv.PublicKey.Bytes() }
func (k *nistExchange) shared(peer []byte) ([]byte, error) {
	pub, err := ecc.ParsePublicKey(k.priv.Curve, peer)
	if err != nil {
		return nil, err
	}
	return k.priv.ECDH(pub)
}

func newKeyExchange(g CurveID, rand io.Reader) (keyExchange, error) {
	switch g {
	case X25519:
		priv := make([]byte, 32)
		if _, err := io.ReadFull(rand, priv); err != nil {
			return nil, err
		}
		pub, err := x25519.PublicKey(priv)
		if err != nil {
			return nil, err
		}
		return &x25519Exchange{priv, pub}, nil
	case P256, P384:
		curve := ecc.P256
		if g == P384 {
			curve = ecc.P384
		}
		buf := make([]byte, curve.Bytes+8)
		if _, err := io.ReadFull(rand, buf); err != nil {
			return nil, err
		}
		d := new(big.Int).SetBytes(buf)
		d.Mod(d, new(big.Int).Sub(curve.N, big.NewInt(1)))
		d.Add(d, big.NewInt(1))
		return &nistExchange{g, ecc.NewPrivateKey(curve, d)}, nil
	}
	return nil, errors.New("unsupported group")
}
