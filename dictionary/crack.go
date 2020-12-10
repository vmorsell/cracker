package dictionary

import (
	"bytes"
	"time"

	"github.com/vmorsell/cracker/cipherlib"
	"github.com/vmorsell/cracker/digestcache"
)

// Strategy defines options for the cracking.
type Strategy struct {
	Cipher cipherlib.Interface
	Cache  *digestcache.DigestCache
}

// Result represents the attack output.
type Result struct {
	Ok        bool
	Hash      []byte
	Password  []byte
	Tries     int
	UsedCache bool
	Duration  time.Duration
}

// Crack executes a Dictionary attack.
func (d *Dictionary) Crack(hash []byte, salt []byte, s *Strategy) *Result {
	start := time.Now()

	if s.Cache != nil {
		if cached := s.Cache.Lookup(hash); cached != nil {
			duration := time.Now().Sub(start)
			return &Result{
				Ok:        true,
				Hash:      hash,
				Password:  cached,
				Tries:     1,
				UsedCache: true,
				Duration:  duration,
			}
		}
	}

	for i, w := range d.Words {
		salted := append(w, salt...)
		h := s.Cipher.Hash(salted)
		if bytes.Equal(hash, h) {
			duration := time.Now().Sub(start)

			if s.Cache != nil {
				s.Cache.Add(hash, w)
			}

			return &Result{
				Ok:       true,
				Hash:     h,
				Password: w,
				Tries:    i + 1,
				Duration: duration,
			}
		}
	}

	// No match
	duration := time.Now().Sub(start)
	return &Result{
		Ok:       false,
		Tries:    len(d.Words),
		Duration: duration,
	}
}
