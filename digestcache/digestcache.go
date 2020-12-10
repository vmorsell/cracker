// Package digestcache handles cipher digest caching.
package digestcache

// Interface defines the public API for DigestCache.
type Interface interface {
	Add(hash []byte, text []byte)
	Lookup(hash []byte) []byte
}

// DigestCache holds the cache data and logic.
type DigestCache struct {
	Records map[string][]byte
}

var _ Interface = &DigestCache{}

// New creates a *DigestCache struct.
func New() *DigestCache {
	r := make(map[string][]byte)
	return &DigestCache{
		Records: r,
	}
}

// Add inserts a record to the cache.
func (dc *DigestCache) Add(hash []byte, text []byte) {
	dc.Records[string(hash)] = text
}

// Lookup finds and returns a record from the cache.
func (dc *DigestCache) Lookup(hash []byte) []byte {
	if r, ok := dc.Records[string(hash)]; ok {
		return r
	}
	return nil
}
