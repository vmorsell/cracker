package bruteforce

import (
	"bytes"
	"time"

	"github.com/vmorsell/cracker-poc/cipherlib"
)

var (
	lowercase = []byte("abcdefghijklmnopqrstuvwxyz")
	uppercase = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	numbers   = []byte("0123456789")
	special   = []byte("!@#$%&.:,;-_")
)

type Strategy struct {
	Cipher    cipherlib.Interface
	Lowercase bool
	Uppercase bool
	Numbers   bool
	Special   bool
	Max       int
}

type Result struct {
	Ok       bool
	Hash     []byte
	Password []byte
	Tries    int
	Time     time.Duration
}

func (b *Bruteforce) Crack(hash []byte, s *Strategy) *Result {
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

	i := 1
	for {
		x := s.Cipher.Hash(curr)
		if bytes.Equal(hash, x) {
			time := time.Now().Sub(start)
			return &Result{
				Ok:       true,
				Hash:     hash,
				Password: curr,
				Tries:    i,
				Time:     time,
			}
		}

		// Build children and append to queue
		for _, v := range lowercase {
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

		i++
	}

	// No match
	time := time.Now().Sub(start)
	return &Result{
		Ok:    false,
		Tries: i,
		Time:  time,
	}
}
