// Package dictionary holds logic for Dictionary cracking attacks.
package dictionary

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
)

// Interface defines the public API exposed by Dictionary
type Interface interface {
	Crack(hash []byte, salt []byte, s *Strategy) *Result
}

// Dictionary is the main struct
type Dictionary struct {
	Words [][]byte
}

var _ Interface = &Dictionary{}

// New loads a dictionary file and returns a Dictionary struct
func New(src string) (*Dictionary, error) {
	if src == "" {
		return nil, errors.New("missing src")
	}

	file, err := os.Open(src)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer file.Close()

	reader := bufio.NewReader(file)

	var words [][]byte
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("readLine: %w", err)
		}

		w := make([]byte, len(line))
		copy(w, line)
		words = append(words, w)
	}
	return &Dictionary{
		Words: words,
	}, nil
}
