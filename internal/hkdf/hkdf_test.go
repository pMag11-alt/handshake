package hkdf

import (
	"encoding/hex"
	"testing"

	"github.com/pMag11-alt/handshake/internal/sha2"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// RFC 5869 test cases 1 and 3.
func TestRFC5869(t *testing.T) {
	cases := []struct{ ikm, salt, info, prk, okm string }{
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9",
			"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
			"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
		},
		{
			"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "", "",
			"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
			"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8",
		},
	}
	for i, c := range cases {
		prk := Extract(sha2.New256, unhex(c.ikm), unhex(c.salt))
		if hex.EncodeToString(prk) != c.prk {
			t.Errorf("case %d PRK: %x", i, prk)
		}
		okm := Expand(sha2.New256, prk, unhex(c.info), len(c.okm)/2)
		if hex.EncodeToString(okm) != c.okm {
			t.Errorf("case %d OKM: %x", i, okm)
		}
	}
}
