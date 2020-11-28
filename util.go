package main

import "fmt"

func shortHash(h []byte) string {
	if len(h) <= 4 {
		return fmt.Sprintf("%x", h)
	}
	prefix := h[:2]
	suffix := h[len(h)-2:]
	return fmt.Sprintf("%x...%x", prefix, suffix)
}
