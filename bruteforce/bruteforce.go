package bruteforce

type Interface interface {
	Crack(hash []byte, salt []byte, s *Strategy) *Result
}

type Bruteforce struct{}

var _ Interface = &Bruteforce{}

func New() *Bruteforce {
	return &Bruteforce{}
}
