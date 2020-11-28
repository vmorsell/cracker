package cipherlib

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
)

type Sha2 struct {
	Bits int
}

var _ Interface = &Sha2{}

var bitsizes = []int{224, 256, 384, 512}

func NewSha2(bits int) (*Sha2, error) {
	for _, v := range bitsizes {
		if bits == v {
			return &Sha2{
				Bits: v,
			}, nil
		}
	}
	return nil, fmt.Errorf("invalid bitsize")
}

// Hash returs the digest for the chosen bitsize
func (s *Sha2) Hash(in []byte) []byte {
	switch s.Bits {
	case 224:
		return execSha224(in)
	case 384:
		return execSha384(in)
	case 512:
		return execSha512(in)
	case 256:
		return execSha256(in)
	}
	return nil
}

func execSha224(in []byte) []byte {
	h := sha256.Sum224(in)
	return h[:]
}

func execSha256(in []byte) []byte {
	h := sha256.Sum256(in)
	return h[:]
}

func execSha384(in []byte) []byte {
	h := sha512.Sum384(in)
	return h[:]
}

func execSha512(in []byte) []byte {
	h := sha512.Sum512(in)
	return h[:]
}
