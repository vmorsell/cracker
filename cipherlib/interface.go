package cipherlib

type Interface interface {
	Hash(s []byte) []byte
}
