package bruteforce

import (
	"bytes"
	"time"

	"github.com/vmorsell/cracker/cipherlib"
)

var (
	lowercase = []byte("abcdefghijklmnopqrstuvwxyz")
	uppercase = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	numbers   = []byte("0123456789")
	special   = []byte("!@#$%&.:,;-_")
)

// Strategy defines options for the cracking method
type Strategy struct {
	Cipher    cipherlib.Interface
	Lowercase bool
	Uppercase bool
	Numbers   bool
	Special   bool
	Min       int
	Max       int
}

// Result is the attack output
type Result struct {
	Ok       bool
	Hash     []byte
	Password []byte
	Tries    int
	Duration time.Duration
}

// Crack executes a Brute Force attack
func (b *Bruteforce) Crack(hash []byte, salt []byte, s *Strategy) *Result {
	start := time.Now()

	var chars []byte
	if s.Lowercase {
		chars = append(chars, lowercase...)
	}
	if s.Uppercase {
		chars = append(chars, uppercase...)
	}
	if s.Numbers {
		chars = append(chars, numbers...)
	}
	if s.Special {
		chars = append(chars, special...)
	}

	queue := [][]byte{}
	var curr []byte

	i := 0
	for {
		if len(curr) >= s.Min {
			i++
			salted := append(curr, salt...)
			x := s.Cipher.Hash(salted)
			if bytes.Equal(hash, x) {
				duration := time.Now().Sub(start)
				return &Result{
					Ok:       true,
					Hash:     hash,
					Password: curr,
					Tries:    i,
					Duration: duration,
				}
			}
		}

		// Build children and append to queue
		for _, v := range chars {
			child := make([]byte, len(curr)+1)
			copy(child, append(curr, v))
			queue = append(queue, child)
		}

		if len(queue) == 0 {
			break
		}

		// Pop first item for next round
		curr = queue[0]
		queue = queue[1:]

		// Break if we exceed the max length
		if len(curr) > s.Max {
			break
		}
	}

	// No match
	duration := time.Now().Sub(start)
	return &Result{
		Ok:       false,
		Tries:    i,
		Duration: duration,
	}
}
