package asn1

import (
	stdasn1 "encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestIntegerRoundTripAgainstStdlib(t *testing.T) {
	for _, v := range []int64{0, 1, 127, 128, 255, 256, 65535, 1 << 40} {
		ours := Integer(big.NewInt(v))
		std, _ := stdasn1.Marshal(big.NewInt(v))
		if string(ours) != string(std) {
			t.Errorf("%d: %x vs %x", v, ours, std)
		}
		got, err := NewReader(ours).BigInt()
		if err != nil || got.Int64() != v {
			t.Errorf("%d: decoded %v %v", v, got, err)
		}
	}
}

func TestOIDRoundTrip(t *testing.T) {
	oids := []OID{{1, 2, 840, 113549, 1, 1, 11}, {2, 5, 29, 17}, {1, 3, 132, 0, 34}, {2, 999, 3}}
	for _, o := range oids {
		std, _ := stdasn1.Marshal(stdasn1.ObjectIdentifier(o))
		if string(ObjectIdentifier(o)) != string(std) {
			t.Errorf("%v: encoding differs from encoding/asn1", o)
		}
		got, err := NewReader(std).OID()
		if err != nil || !got.Equal(o) {
			t.Errorf("%v: decoded %v %v", o, got, err)
		}
	}
}

func TestLongLengths(t *testing.T) {
	body := make([]byte, 300)
	enc := OctetString(body)
	if enc[1] != 0x82 || enc[2] != 0x01 || enc[3] != 0x2c {
		t.Fatalf("length bytes: %x", enc[:4])
	}
	got, err := NewReader(enc).OctetString()
	if err != nil || len(got) != 300 {
		t.Fatalf("decode: %v", err)
	}
}

func TestRejectsNonDER(t *testing.T) {
	bad := [][]byte{
		{0x04, 0x81, 0x05, 1, 2, 3, 4, 5}, // long form for a short length
		{0x04, 0x80, 0x00, 0x00},          // indefinite length
		{0x04, 0x05, 1, 2},                // truncated
		{0x02, 0x02, 0x00, 0x01},          // non-minimal integer
	}
	for i, b := range bad {
		r := NewReader(b)
		if _, err := r.Read(); err == nil && i < 3 {
			t.Errorf("case %d accepted", i)
		}
	}
	if _, err := NewReader(bad[3]).BigInt(); err == nil {
		t.Error("non-minimal integer accepted")
	}
}

func TestTimes(t *testing.T) {
	cases := []time.Time{
		time.Date(1999, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC),
		time.Date(2051, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	for _, want := range cases {
		got, err := NewReader(UTCTimeOrGeneralized(want)).Time()
		if err != nil || !got.Equal(want) {
			t.Errorf("%v: got %v %v", want, got, err)
		}
	}
}

func TestBitStringFlags(t *testing.T) {
	// keyUsage digitalSignature (bit 0) and keyCertSign (bit 5): 0b1000_0100.
	flags, err := BitStringFlags([]byte{0x01, 0x84})
	if err != nil || flags != 1|1<<5 {
		t.Fatalf("flags %b %v", flags, err)
	}
}
