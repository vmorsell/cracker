package bruteforce

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/vmorsell/cracker/cipherlib"
)

func TestCrack(t *testing.T) {
	b := &Bruteforce{}
	cipher, err := cipherlib.NewSha2(256)
	if err != nil {
		t.Fatalf("cipher: %s", err)
	}

	tests := []struct {
		name         string
		hash         []byte
		salt         []byte
		strategy     *Strategy
		wantOk       bool
		wantPassword []byte
	}{
		{
			name: "ok - number",
			hash: []byte("4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce"), // 3
			strategy: &Strategy{
				Cipher:  cipher,
				Numbers: true,
				Max:     1,
			},
			wantOk:       true,
			wantPassword: []byte("3"),
		},
		{
			name: "ok - lowercase",
			hash: []byte("252f10c83610ebca1a059c0bae8255eba2f95be4d1d7bcfa89d7248a82d9f111"), // f
			strategy: &Strategy{
				Cipher:    cipher,
				Lowercase: true,
				Max:       1,
			},
			wantOk:       true,
			wantPassword: []byte("f"),
		},
		{
			name: "ok - uppercase",
			hash: []byte("6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d"), // C
			strategy: &Strategy{
				Cipher:    cipher,
				Uppercase: true,
				Max:       1,
			},
			wantOk:       true,
			wantPassword: []byte("C"),
		},
		{
			name: "ok - special",
			hash: []byte("09fc96082d34c2dfc1295d92073b5ea1dc8ef8da95f14dfded011ffb96d3e54b"), // $
			strategy: &Strategy{
				Cipher:  cipher,
				Special: true,
				Max:     1,
			},
			wantOk:       true,
			wantPassword: []byte("$"),
		},
		{
			name: "not found - not in charset",
			hash: []byte("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"), // a
			strategy: &Strategy{
				Cipher:  cipher,
				Numbers: true, // Only numbers - will not match 'a' hash
				Max:     1,
			},
			wantOk: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := decodeHex(tt.hash)
			if err != nil {
				t.Fatalf("decode hash: %s", err)
			}

			res := b.Crack(h, tt.salt, tt.strategy)

			t.Run("check ok", func(t *testing.T) {
				if got, want := res.Ok, tt.wantOk; got != want {
					t.Fatalf("got %t want %t", got, want)
				}
			})

			t.Run("check password", func(t *testing.T) {
				if got, want := res.Password, tt.wantPassword; bytes.Equal(got, want) == false {
					t.Fatalf("got %v want %v", got, want)
				}
			})
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
