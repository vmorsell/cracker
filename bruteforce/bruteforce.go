package bruteforce

type Interface interface {
	Crack(in []byte, s *Strategy) *Result
}

type Bruteforce struct{}

var _ Interface = &Bruteforce{}

func New() *Bruteforce {
	return &Bruteforce{}
}
