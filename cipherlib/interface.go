package cipherlib

// Interface defines the cipher API
type Interface interface {
	Hash(s []byte) []byte
}
