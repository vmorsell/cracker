// Package bruteforce holds logic for Brute Force cracking attacks.
package bruteforce

// Interface defines the public API for Bruteforce.
type Interface interface {
	Crack(hash []byte, salt []byte, s *Strategy) *Result
}

// Bruteforce is the engine for the Brute Force attack.
type Bruteforce struct{}

var _ Interface = &Bruteforce{}

// New creates a *Bruteforce struct.
func New() *Bruteforce {
	return &Bruteforce{}
}
