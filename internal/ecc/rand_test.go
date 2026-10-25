package ecc

import "crypto/rand"

type cryptoRand struct{}

func (cryptoRand) Read(p []byte) (int, error) { return rand.Read(p) }
