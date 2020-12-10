package dataset

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

var (
	aSHA256     = []byte("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb")
	aSHA256Dec  = []byte{202, 151, 129, 18, 202, 27, 189, 202, 250, 194, 49, 179, 154, 35, 220, 77, 167, 134, 239, 248, 20, 124, 78, 114, 185, 128, 119, 133, 175, 238, 72, 187}
	abSHA256    = []byte("fb8e20fc2e4c3f248c60c39bd652f3c1347298bb977b8b4d5903b85055620603")
	abSHA256Dec = []byte{251, 142, 32, 252, 46, 76, 63, 36, 140, 96, 195, 155, 214, 82, 243, 193, 52, 114, 152, 187, 151, 123, 139, 77, 89, 3, 184, 80, 85, 98, 6, 3}
)

func TestHasNext(t *testing.T) {
	tests := []struct {
		name   string
		reader *bytes.Reader
		want   bool
	}{
		{
			name:   "has unread data",
			reader: bytes.NewReader([]byte("abc")),
			want:   true,
		},
		{
			name:   "empty buffer",
			reader: bytes.NewReader([]byte{}),
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := &Dataset{
				reader: bufio.NewReader(tt.reader),
			}

			if got, want := ds.HasNext(), tt.want; got != want {
				t.Fatalf("got %t want %t", got, want)
			}
		})
	}
}

func TestNext(t *testing.T) {
	aSHA256Dec, err := decodeHex(aSHA256)
	if err != nil {
		t.Fatalf("decode a: %s", err)
	}
	fmt.Println(aSHA256Dec)

	abSHA256Dec, err := decodeHex(abSHA256)
	if err != nil {
		t.Fatalf("decode ab: %s", err)
	}

	tests := []struct {
		name   string
		reader *bytes.Reader
		want   *Item
		err    error
	}{
		{
			name: "ok - only hash",
			reader: bytes.NewReader(
				combineByteSlices(
					aSHA256,
					[]byte("\n"),
					abSHA256,
				),
			),
			want: &Item{
				Hash: aSHA256Dec,
			},
		},
		{
			name: "ok - hash and salt",
			reader: bytes.NewReader(
				combineByteSlices(
					abSHA256,
					[]byte(","),
					[]byte("b"),
					[]byte("\n"),
				),
			),
			want: &Item{
				Hash: abSHA256Dec,
				Salt: []byte("b"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds := &Dataset{
				reader: bufio.NewReader(tt.reader),
			}

			res, err := ds.Next()

			t.Run("check result", func(t *testing.T) {
				if got, want := res, tt.want; reflect.DeepEqual(got, want) == false {
					t.Fatalf("got %+v want %+v", got, want)
				}
			})

			t.Run("check error", func(t *testing.T) {
				if got, want := err, tt.err; got != want {
					t.Fatalf("got %s want %s", got, want)
				}
			})
		})
	}
}

func TestDecodeHex(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want []byte
		err  error
	}{
		{
			name: "ok",
			in:   aSHA256,
			want: aSHA256Dec,
		},
		{
			name: "decode error",
			in:   []byte("invalid"),
			err:  hex.InvalidByteError('i'),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := decodeHex(tt.in)

			t.Run("check result", func(t *testing.T) {
				if got, want := res, tt.want; bytes.Equal(got, want) == false {
					t.Fatalf("got %v want %v", got, want)
				}
			})

			t.Run("check error", func(t *testing.T) {
				if errors.Is(err, tt.err) == false {
					t.Fatalf("got %s want %s", err, tt.err)
				}
			})
		})
	}
}

func combineByteSlices(slices ...[]byte) []byte {
	var res []byte
	for _, s := range slices {
		res = append(res, s...)
	}
	return res
}
