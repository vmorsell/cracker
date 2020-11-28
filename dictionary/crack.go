package dictionary

import (
	"bytes"
	"time"

	"github.com/vmorsell/cracker/cipherlib"
)

type Strategy struct {
	Cipher cipherlib.Interface
}

type Result struct {
	Ok       bool
	Hash     []byte
	Password []byte
	Tries    int
	Time     time.Duration
}

// Crack tries to find the original password using the loaded dictionary
func (d *Dictionary) Crack(hash []byte, s *Strategy) *Result {
	start := time.Now()

	for i, w := range d.Words {
		h := s.Cipher.Hash(w)
		if bytes.Equal(hash, h) {
			time := time.Now().Sub(start)
			return &Result{
				Ok:       true,
				Hash:     h,
				Password: w,
				Tries:    i + 1,
				Time:     time,
			}
		}
	}

	// No match
	time := time.Now().Sub(start)
	return &Result{
		Ok:    false,
		Tries: len(d.Words),
		Time:  time,
	}
}
