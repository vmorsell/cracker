package dictionary

import (
	"bytes"
	"time"

	"github.com/vmorsell/cracker/cipherlib"
)

// Strategy defines options for the cracking method
type Strategy struct {
	Cipher cipherlib.Interface
}

// Result is the attack output
type Result struct {
	Ok       bool
	Hash     []byte
	Password []byte
	Tries    int
	Time     time.Duration
}

// Crack executes a Dictionary attack
func (d *Dictionary) Crack(hash []byte, salt []byte, s *Strategy) *Result {
	start := time.Now()

	for i, w := range d.Words {
		salted := append(w, salt...)
		h := s.Cipher.Hash(salted)
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
