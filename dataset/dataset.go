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

type Interface interface {
	HasNext() bool
	Next() (*Item, error)
}

type Dataset struct {
	LinesRead int
	file      *os.File
	reader    *bufio.Reader
}

var _ Interface = &Dataset{}

var delimiter = []byte(",")

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

func (ds *Dataset) HasNext() bool {
	_, err := ds.reader.Peek(1)
	if err != nil {
		return false
	}
	return true
}

type Item struct {
	Username string
	Hash     []byte
	Salt     []byte
}

func (ds *Dataset) Next() (*Item, error) {
	line, _, err := ds.reader.ReadLine()
	if err == io.EOF {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	record := bytes.Split(line, delimiter)

	hash, err := decodeHex(record[1])
	if err != nil {
		return nil, fmt.Errorf("decodeHex: %w", err)
	}

	ds.LinesRead++
	return &Item{
		Username: string(record[0]),
		Hash:     hash,
		Salt:     record[2],
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
