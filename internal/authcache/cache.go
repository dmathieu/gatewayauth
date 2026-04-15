// Package authcache provides a thread-safe, size-bounded in-memory cache for
// auth results. Entries are evicted by LRU when the cache is full; TTL is
// enforced on reads.
package authcache

import (
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/elastic/go-freelru"
)

type entry struct {
	err       error
	expiresAt time.Time
}

func hashString(s string) uint32 {
	return uint32(xxhash.Sum64String(s))
}

// Cache stores auth results keyed by Authorization header value.
// 5xx responses must not be cached; all other outcomes (success or 4xx) are
// cached for the configured TTL. When the cache reaches capacity, the
// least-recently-used entry is evicted automatically.
type Cache struct {
	lru *freelru.SyncedLRU[string, entry]
	ttl time.Duration
}

// New returns a Cache with the given TTL and maximum number of entries.
func New(ttl time.Duration, size int) *Cache {
	lru, err := freelru.NewSynced[string, entry](uint32(size), hashString)
	if err != nil {
		// NewSynced only errors on size <= 0, which Validate prevents.
		panic(err)
	}
	return &Cache{lru: lru, ttl: ttl}
}

// Get returns the cached error for key and true if a non-expired entry exists.
// A nil error means the request was previously granted.
func (c *Cache) Get(key string) (error, bool) {
	e, ok := c.lru.Get(key)
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.err, true
}

// Set stores err for key, expiring after the configured TTL.
func (c *Cache) Set(key string, err error) {
	c.lru.Add(key, entry{err: err, expiresAt: time.Now().Add(c.ttl)})
}
