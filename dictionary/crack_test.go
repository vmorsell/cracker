package dictionary

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/vmorsell/cracker/cipherlib/sha2"
)

func TestCrack(t *testing.T) {
	d := &Dictionary{}
	cipher, err := sha2.New(256)
	if err != nil {
		t.Fatalf("cipher: %s", err)
	}

	tests := []struct {
		name         string
		words        [][]byte
		hash         []byte
		salt         []byte
		strategy     *Strategy
		wantOk       bool
		wantPassword []byte
	}{
		{
			name:  "ok - found",
			words: [][]byte{[]byte("a")},
			hash:  []byte("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
			strategy: &Strategy{
				Cipher: cipher,
			},
			wantOk:       true,
			wantPassword: []byte("a"),
		},
		{
			name:  "ok - not found",
			words: [][]byte{[]byte("a")},
			hash:  []byte("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
			strategy: &Strategy{
				Cipher: cipher,
			},
			wantOk: false,
		},
	}

	for _, tt := range tests {
		d.Words = tt.words

		h, err := decodeHex(tt.hash)
		if err != nil {
			t.Fatalf("decode hash: %s", err)
		}

		res := d.Crack(h, tt.salt, tt.strategy)

		t.Run("ok", func(t *testing.T) {
			if got, want := res.Ok, tt.wantOk; got != want {
				t.Fatalf("got %t want %t", got, want)
			}
		})

		t.Run("password", func(t *testing.T) {
			if got, want := res.Password, tt.wantPassword; bytes.Equal(got, want) == false {
				t.Fatalf("got %v want %v", got, want)
			}
		})
	}
}

func decodeHex(in []byte) ([]byte, error) {
	res := make([]byte, hex.DecodedLen(len(in)))
	n, err := hex.Decode(res, in)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return res[:n], nil
}
