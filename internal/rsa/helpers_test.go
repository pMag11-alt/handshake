package rsa

import (
	"crypto/rand"
	"math/big"
)

type bigInt = big.Int

type randReader struct{}

func (randReader) Read(p []byte) (int, error) { return rand.Read(p) }
