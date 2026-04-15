package authcache

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCache_MissOnEmpty(t *testing.T) {
	t.Parallel()
	c := New(time.Minute)
	_, ok := c.Get("token")
	assert.False(t, ok)
}

func TestCache_HitAfterSet(t *testing.T) {
	t.Parallel()
	c := New(time.Minute)

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
	c := New(time.Millisecond)
	c.Set("token", nil)
	time.Sleep(5 * time.Millisecond)
	_, ok := c.Get("token")
	assert.False(t, ok)
}
