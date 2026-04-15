package authcache

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCache_MissOnEmpty(t *testing.T) {
	t.Parallel()
	c := New(time.Minute, 10)
	_, ok := c.Get("token")
	assert.False(t, ok)
}

func TestCache_HitAfterSet(t *testing.T) {
	t.Parallel()
	c := New(time.Minute, 10)

	c.Set("token", nil)
	err, ok := c.Get("token")
	assert.True(t, ok)
	assert.NoError(t, err)

	authErr := errors.New("denied")
	c.Set("bad", authErr)
	err, ok = c.Get("bad")
	assert.True(t, ok)
	assert.Equal(t, authErr, err)
}

func TestCache_ExpiredEntry(t *testing.T) {
	t.Parallel()
	c := New(time.Millisecond, 10)
	c.Set("token", nil)
	time.Sleep(5 * time.Millisecond)
	_, ok := c.Get("token")
	assert.False(t, ok)
}

func TestCache_LRUEviction(t *testing.T) {
	t.Parallel()
	c := New(time.Minute, 2)

	c.Set("a", nil)
	c.Set("b", nil)
	// Adding a third entry evicts the least-recently-used ("a").
	c.Set("c", nil)

	_, ok := c.Get("a")
	assert.False(t, ok, "expected 'a' to be evicted")
	_, ok = c.Get("b")
	assert.True(t, ok)
	_, ok = c.Get("c")
	assert.True(t, ok)
}
