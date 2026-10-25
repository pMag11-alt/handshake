// Package asn1 reads and writes the subset of DER (ITU-T X.690) used by
// X.509 certificates and private keys.
package asn1

import (
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// Universal and context-specific tags used in certificates.
const (
	TagBoolean         = 0x01
	TagInteger         = 0x02
	TagBitString       = 0x03
	TagOctetString     = 0x04
	TagNull            = 0x05
	TagOID             = 0x06
	TagUTF8String      = 0x0c
	TagPrintableString = 0x13
	TagT61String       = 0x14
	TagIA5String       = 0x16
	TagUTCTime         = 0x17
	TagGeneralizedTime = 0x18
	TagBMPString       = 0x1e
	TagSequence        = 0x30
	TagSet             = 0x31
)

// ContextSpecific returns the tag byte for [n], constructed or primitive.
func ContextSpecific(n int, constructed bool) byte {
	t := byte(0x80 | n)
	if constructed {
		t |= 0x20
	}
	return t
}

var ErrMalformed = errors.New("asn1: malformed DER")

// Reader walks a sequence of DER elements.
type Reader struct{ data []byte }

func NewReader(data []byte) *Reader { return &Reader{data} }

func (r *Reader) Empty() bool { return len(r.data) == 0 }

// PeekTag returns the next tag without consuming it, or 0 if empty.
func (r *Reader) PeekTag() byte {
	if len(r.data) == 0 {
		return 0
	}
	return r.data[0]
}

// Element is one decoded tag-length-value.
type Element struct {
	Tag      byte
	Contents []byte
	Raw      []byte // the full encoding, including tag and length
}

// Read consumes the next element.
func (r *Reader) Read() (Element, error) {
	d := r.data
	if len(d) < 2 {
		return Element{}, ErrMalformed
	}
	tag := d[0]
	if tag&0x1f == 0x1f {
		return Element{}, errors.New("asn1: multi-byte tags are not supported")
	}
	length := int(d[1])
	header := 2
	if length&0x80 != 0 {
		n := length & 0x7f
		if n == 0 || n > 4 || len(d) < 2+n {
			return Element{}, ErrMalformed // indefinite or absurd lengths
		}
		length = 0
		for _, b := range d[2 : 2+n] {
			length = length<<8 | int(b)
		}
		if length < 0x80 || (n > 1 && d[2] == 0) {
			return Element{}, ErrMalformed // not minimal, so not DER
		}
		header += n
	}
	if length < 0 || len(d)-header < length {
		return Element{}, ErrMalformed
	}
	e := Element{Tag: tag, Contents: d[header : header+length], Raw: d[:header+length]}
	r.data = d[header+length:]
	return e, nil
}

// Expect consumes the next element and checks its tag.
func (r *Reader) Expect(tag byte) (Element, error) {
	e, err := r.Read()
	if err != nil {
		return e, err
	}
	if e.Tag != tag {
		return e, fmt.Errorf("asn1: expected tag 0x%02x, found 0x%02x", tag, e.Tag)
	}
	return e, nil
}

// Sequence consumes a SEQUENCE and returns a reader over its contents.
func (r *Reader) Sequence() (*Reader, error) {
	e, err := r.Expect(TagSequence)
	if err != nil {
		return nil, err
	}
	return NewReader(e.Contents), nil
}

// Optional consumes the next element only if it has the given tag.
func (r *Reader) Optional(tag byte) (Element, bool, error) {
	if r.PeekTag() != tag {
		return Element{}, false, nil
	}
	e, err := r.Read()
	return e, err == nil, err
}

func (r *Reader) BigInt() (*big.Int, error) {
	e, err := r.Expect(TagInteger)
	if err != nil {
		return nil, err
	}
	return ParseInt(e.Contents)
}

// ParseInt decodes a two's-complement INTEGER body.
func ParseInt(b []byte) (*big.Int, error) {
	if len(b) == 0 || (len(b) > 1 && (b[0] == 0 && b[1] < 0x80 || b[0] == 0xff && b[1] >= 0x80)) {
		return nil, ErrMalformed
	}
	v := new(big.Int).SetBytes(b)
	if b[0]&0x80 != 0 {
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(len(b)*8)))
	}
	return v, nil
}

func (r *Reader) Int() (int, error) {
	v, err := r.BigInt()
	if err != nil {
		return 0, err
	}
	if !v.IsInt64() || v.Int64() > 1<<31 || v.Int64() < -(1<<31) {
		return 0, errors.New("asn1: integer too large")
	}
	return int(v.Int64()), nil
}

func (r *Reader) Bool() (bool, error) {
	e, err := r.Expect(TagBoolean)
	if err != nil {
		return false, err
	}
	if len(e.Contents) != 1 || (e.Contents[0] != 0 && e.Contents[0] != 0xff) {
		return false, ErrMalformed
	}
	return e.Contents[0] == 0xff, nil
}

// OID is an object identifier such as 1.2.840.113549.1.1.11.
type OID []int

func (o OID) String() string {
	parts := make([]string, len(o))
	for i, v := range o {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ".")
}

func (o OID) Equal(other OID) bool {
	if len(o) != len(other) {
		return false
	}
	for i := range o {
		if o[i] != other[i] {
			return false
		}
	}
	return true
}

func ParseOID(b []byte) (OID, error) {
	if len(b) == 0 {
		return nil, ErrMalformed
	}
	var out OID
	v := 0
	for i, c := range b {
		if v == 0 && c == 0x80 {
			return nil, ErrMalformed // non-minimal
		}
		v = v<<7 | int(c&0x7f)
		if v > 1<<28 {
			return nil, ErrMalformed
		}
		if c&0x80 == 0 {
			if len(out) == 0 {
				first := min(v/40, 2)
				out = append(out, first, v-40*first)
			} else {
				out = append(out, v)
			}
			v = 0
		} else if i == len(b)-1 {
			return nil, ErrMalformed
		}
	}
	return out, nil
}

func (r *Reader) OID() (OID, error) {
	e, err := r.Expect(TagOID)
	if err != nil {
		return nil, err
	}
	return ParseOID(e.Contents)
}

// BitString returns the bytes of a BIT STRING with no unused bits.
func (r *Reader) BitString() ([]byte, error) {
	e, err := r.Expect(TagBitString)
	if err != nil {
		return nil, err
	}
	if len(e.Contents) == 0 || e.Contents[0] != 0 {
		return nil, errors.New("asn1: BIT STRING with unused bits")
	}
	return e.Contents[1:], nil
}

// BitStringFlags returns a BIT STRING interpreted as flags, bit 0 first,
// as used by keyUsage.
func BitStringFlags(contents []byte) (int, error) {
	if len(contents) == 0 || contents[0] > 7 {
		return 0, ErrMalformed
	}
	flags := 0
	for i, b := range contents[1:] {
		for bit := 0; bit < 8; bit++ {
			if b&(0x80>>bit) != 0 {
				flags |= 1 << (i*8 + bit)
			}
		}
	}
	return flags, nil
}

func (r *Reader) OctetString() ([]byte, error) {
	e, err := r.Expect(TagOctetString)
	return e.Contents, err
}

// Time parses a UTCTime or GeneralizedTime in the Z (UTC) form DER requires.
func (r *Reader) Time() (time.Time, error) {
	e, err := r.Read()
	if err != nil {
		return time.Time{}, err
	}
	s := string(e.Contents)
	switch e.Tag {
	case TagUTCTime:
		t, err := time.Parse("060102150405Z", s)
		if err != nil {
			return time.Time{}, ErrMalformed
		}
		// Two-digit years: 50-99 mean 19xx (RFC 5280 section 4.1.2.5.1).
		if t.Year() >= 2050 {
			t = t.AddDate(-100, 0, 0)
		}
		return t, nil
	case TagGeneralizedTime:
		t, err := time.Parse("20060102150405Z", s)
		if err != nil {
			return time.Time{}, ErrMalformed
		}
		return t, nil
	}
	return time.Time{}, fmt.Errorf("asn1: expected a time, found tag 0x%02x", e.Tag)
}

// String decodes the string types names use.
func String(e Element) (string, error) {
	switch e.Tag {
	case TagUTF8String, TagPrintableString, TagIA5String, TagT61String:
		return string(e.Contents), nil
	case TagBMPString:
		if len(e.Contents)%2 != 0 {
			return "", ErrMalformed
		}
		var sb strings.Builder
		for i := 0; i < len(e.Contents); i += 2 {
			sb.WriteRune(rune(e.Contents[i])<<8 | rune(e.Contents[i+1]))
		}
		return sb.String(), nil
	}
	return "", fmt.Errorf("asn1: not a string type: 0x%02x", e.Tag)
}

// ---- encoding ---------------------------------------------------------------------

// TLV encodes one element.
func TLV(tag byte, contents ...[]byte) []byte {
	n := 0
	for _, c := range contents {
		n += len(c)
	}
	out := []byte{tag}
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	case n < 0x10000:
		out = append(out, 0x82, byte(n>>8), byte(n))
	default:
		out = append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	for _, c := range contents {
		out = append(out, c...)
	}
	return out
}

func Sequence(children ...[]byte) []byte { return TLV(TagSequence, children...) }
func Set(children ...[]byte) []byte      { return TLV(TagSet, children...) }

// Explicit wraps children in an explicit context-specific tag [n].
func Explicit(n int, children ...[]byte) []byte {
	return TLV(ContextSpecific(n, true), children...)
}

func Integer(v *big.Int) []byte {
	if v.Sign() < 0 {
		panic("asn1: negative integers are not needed here")
	}
	b := v.Bytes()
	if len(b) == 0 || b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return TLV(TagInteger, b)
}

func SmallInt(v int) []byte { return Integer(big.NewInt(int64(v))) }

func Boolean(v bool) []byte {
	if v {
		return TLV(TagBoolean, []byte{0xff})
	}
	return TLV(TagBoolean, []byte{0})
}

func Null() []byte { return []byte{TagNull, 0} }

func ObjectIdentifier(o OID) []byte {
	body := encodeBase128(o[0]*40 + o[1])
	for _, v := range o[2:] {
		body = append(body, encodeBase128(v)...)
	}
	return TLV(TagOID, body)
}

func encodeBase128(v int) []byte {
	out := []byte{byte(v & 0x7f)}
	for v >>= 7; v > 0; v >>= 7 {
		out = append([]byte{byte(v&0x7f) | 0x80}, out...)
	}
	return out
}

func BitString(b []byte) []byte   { return TLV(TagBitString, []byte{0}, b) }
func OctetString(b []byte) []byte { return TLV(TagOctetString, b) }
func UTF8String(s string) []byte  { return TLV(TagUTF8String, []byte(s)) }

// UTCTimeOrGeneralized encodes t the way RFC 5280 requires: UTCTime
// through 2049, GeneralizedTime from 2050.
func UTCTimeOrGeneralized(t time.Time) []byte {
	t = t.UTC()
	if t.Year() < 2050 {
		return TLV(TagUTCTime, []byte(t.Format("060102150405Z")))
	}
	return TLV(TagGeneralizedTime, []byte(t.Format("20060102150405Z")))
}
