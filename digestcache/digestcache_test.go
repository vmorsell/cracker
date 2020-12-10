package digestcache

import (
	"bytes"
	"reflect"
	"testing"
)

func TestAdd(t *testing.T) {
	dc := New()

	hash := []byte("a")
	text := []byte("b")

	dc.Add(hash, text)

	want := map[string][]byte{string(hash): text}
	if got := dc.Records; reflect.DeepEqual(got, want) == false {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestGet(t *testing.T) {
	dc := New()

	hash := []byte("a")
	text := []byte("b")
	dc.Add(hash, text)

	t.Run("ok - found", func(t *testing.T) {
		if got, want := dc.Lookup(hash), text; bytes.Equal(got, want) == false {
			t.Fatalf("got %v want %v", got, want)
		}
	})

	t.Run("ok - not found", func(t *testing.T) {
		if got := dc.Lookup([]byte("c")); got != nil {
			t.Fatalf("got %v want %v", got, nil)
		}
	})
}
