// Package pem reads and writes PEM blocks (RFC 7468).
package pem

import (
	"bytes"
	"encoding/base64"
	"strings"
)

type Block struct {
	Type  string
	Bytes []byte
}

// Decode returns every well-formed block in data, ignoring text between them.
func Decode(data []byte) []Block {
	var blocks []Block
	for {
		start := bytes.Index(data, []byte("-----BEGIN "))
		if start < 0 {
			return blocks
		}
		data = data[start+len("-----BEGIN "):]
		eol := bytes.Index(data, []byte("-----"))
		if eol < 0 {
			return blocks
		}
		typ := string(data[:eol])
		data = data[eol+5:]
		end := bytes.Index(data, []byte("-----END "+typ+"-----"))
		if end < 0 {
			return blocks
		}
		body := strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, string(data[:end]))
		data = data[end:]
		der, err := base64.StdEncoding.DecodeString(body)
		if err == nil {
			blocks = append(blocks, Block{Type: typ, Bytes: der})
		}
	}
}

// Encode formats a block with 64-character lines.
func Encode(b Block) []byte {
	var out bytes.Buffer
	out.WriteString("-----BEGIN " + b.Type + "-----\n")
	s := base64.StdEncoding.EncodeToString(b.Bytes)
	for len(s) > 64 {
		out.WriteString(s[:64] + "\n")
		s = s[64:]
	}
	if len(s) > 0 {
		out.WriteString(s + "\n")
	}
	out.WriteString("-----END " + b.Type + "-----\n")
	return out.Bytes()
}
