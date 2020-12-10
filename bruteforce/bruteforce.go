// Package bruteforce holds logic for Brute Force cracking attacks.
package bruteforce

// Interface defines the public API exposed by this package
type Interface interface {
	Crack(hash []byte, salt []byte, s *Strategy) *Result
}

// Bruteforce is the main struct
type Bruteforce struct{}

var _ Interface = &Bruteforce{}

// New returns a Bruteforce struct
func New() *Bruteforce {
	return &Bruteforce{}
}
