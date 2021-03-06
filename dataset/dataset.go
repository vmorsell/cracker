// Package dataset handles opening and streaming of hash datasets.
package dataset

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// Interface defines the public API for Dataset.
type Interface interface {
	HasNext() bool
	Next() (*Item, error)
}

// Dataset is the engine for opening and streaming a hash dataset.
//
// Note that the zero value for Dataset is not a valid configuration.
// Create a Dataset struct using New().
type Dataset struct {
	LinesRead int
	file      *os.File
	reader    *bufio.Reader
}

var _ Interface = &Dataset{}

var delimiter = []byte(",")

// New creates a *Dataset from a dataset file source.
func New(src string) (*Dataset, error) {
	if src == "" {
		return nil, errors.New("missing src")
	}

	file, err := os.Open(src)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	reader := bufio.NewReader(file)

	return &Dataset{
		file:   file,
		reader: reader,
	}, nil
}

// HasNext returns true if there's unread data left in the dataset buffer.
func (ds *Dataset) HasNext() bool {
	_, err := ds.reader.Peek(1)
	if err != nil {
		return false
	}
	ds.file.Close()
	return true
}

// Item represents a record in the dataset.
type Item struct {
	Hash []byte
	Salt []byte
}

// Next returns the next record from the dataset buffer.
func (ds *Dataset) Next() (*Item, error) {
	line, _, err := ds.reader.ReadLine()
	if err == io.EOF {
		ds.file.Close()
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	record := bytes.Split(line, delimiter)

	var hexHash, salt []byte
	hexHash = record[0]

	// Use salt if present in the dataset
	if len(record) == 2 {
		salt = record[1]
	}

	hash, err := decodeHex(hexHash)
	if err != nil {
		return nil, fmt.Errorf("decodeHex: %w", err)
	}

	ds.LinesRead++
	return &Item{
		Hash: hash,
		Salt: salt,
	}, nil
}

func decodeHex(in []byte) ([]byte, error) {
	res := make([]byte, hex.DecodedLen(len(in)))
	n, err := hex.Decode(res, in)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return res[:n], nil
}
