// Package authcache provides a thread-safe in-memory cache for auth results.
package authcache

import (
	"sync"
	"time"
)

type entry struct {
	err       error
	expiresAt time.Time
}

// Cache stores auth results keyed by Authorization header value.
// 5xx responses must not be cached; all other outcomes (success or 4xx) are
// cached for the configured TTL.
type Cache struct {
	mu      sync.RWMutex
	entries map[string]entry
	ttl     time.Duration
}

// New returns a Cache with the given TTL.
func New(ttl time.Duration) *Cache {
	return &Cache{
		entries: make(map[string]entry),
		ttl:     ttl,
	}
}

// Get returns the cached error for key and true if a non-expired entry exists.
// A nil error means the request was previously granted.
func (c *Cache) Get(key string) (error, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, false
	}
	return e.err, true
}

// Set stores err for key, expiring after the configured TTL.
func (c *Cache) Set(key string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = entry{err: err, expiresAt: time.Now().Add(c.ttl)}
}
