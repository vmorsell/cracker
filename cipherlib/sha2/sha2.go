// Package sha2 holds logic for SHA2 hashing.
package sha2

import (
	"crypto/sha256"
	"crypto/sha512"
	"fmt"

	"github.com/vmorsell/cracker/cipherlib"
)

// SHA2 represents the SHA2 cipher method.
//
// Note that the zero value for SHA2 is not a valid configuration. Create a
// SHA2 struct using New().
type SHA2 struct {
	Bits int
}

var _ cipherlib.Interface = &SHA2{}

// Bitsizes defines the valid SHA2 bitsizes.
var Bitsizes = []int{224, 256, 384, 512}

// New creates a *SHA2 struct from a cipher bitsize.
func New(bits int) (*SHA2, error) {
	for _, v := range Bitsizes {
		if bits == v {
			return &SHA2{
				Bits: v,
			}, nil
		}
	}
	return nil, fmt.Errorf("invalid bitsize")
}

// Hash calculates the SHA2 digest.
func (s *SHA2) Hash(in []byte) []byte {
	switch s.Bits {
	case 224:
		return execSHA224(in)
	case 384:
		return execSHA384(in)
	case 512:
		return execSHA512(in)
	case 256:
		return execSHA256(in)
	}
	return nil
}

func execSHA224(in []byte) []byte {
	h := sha256.Sum224(in)
	return h[:]
}

func execSHA256(in []byte) []byte {
	h := sha256.Sum256(in)
	return h[:]
}

func execSHA384(in []byte) []byte {
	h := sha512.Sum384(in)
	return h[:]
}

func execSHA512(in []byte) []byte {
	h := sha512.Sum512(in)
	return h[:]
}
