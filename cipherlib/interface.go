// Package cipherlib holds available cipher methods.
package cipherlib

// Interface defines the public API for ciphers.
type Interface interface {
	Hash(s []byte) []byte
}
