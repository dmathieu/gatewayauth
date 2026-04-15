package verifier

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		serverStatus int
		wantErr      bool
	}{
		{name: "200 grants access", serverStatus: http.StatusOK},
		{name: "401 denies access", serverStatus: http.StatusUnauthorized, wantErr: true},
		{name: "403 denies access", serverStatus: http.StatusForbidden, wantErr: true},
		{name: "500 returns error", serverStatus: http.StatusInternalServerError, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.serverStatus)
			}))
			t.Cleanup(srv.Close)

			v := New(srv.URL, 0)
			err := v.Verify(context.Background(), "Bearer token")
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerify_ForwardsAuthorizationHeader(t *testing.T) {
	t.Parallel()

	var received string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	v := New(srv.URL, 0)
	require.NoError(t, v.Verify(context.Background(), "Bearer secret"))
	assert.Equal(t, "Bearer secret", received)
}

func TestVerify_CachesSuccessAndDenial(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") == "Bearer good" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	t.Cleanup(srv.Close)

	v := New(srv.URL, time.Minute)

	require.NoError(t, v.Verify(context.Background(), "Bearer good"))
	assert.EqualValues(t, 1, calls.Load())

	// Second call served from cache.
	require.NoError(t, v.Verify(context.Background(), "Bearer good"))
	assert.EqualValues(t, 1, calls.Load())

	// Denied tokens are also cached.
	assert.Error(t, v.Verify(context.Background(), "Bearer bad"))
	assert.EqualValues(t, 2, calls.Load())

	assert.Error(t, v.Verify(context.Background(), "Bearer bad"))
	assert.EqualValues(t, 2, calls.Load())
}

func TestVerify_DoesNotCache5xx(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	v := New(srv.URL, time.Minute)

	assert.Error(t, v.Verify(context.Background(), "Bearer token"))
	assert.EqualValues(t, 1, calls.Load())

	// Must hit the endpoint again — 5xx must not be cached.
	assert.Error(t, v.Verify(context.Background(), "Bearer token"))
	assert.EqualValues(t, 2, calls.Load())
}

func TestVerify_NoCacheWhenTTLIsZero(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	v := New(srv.URL, 0)
	require.NoError(t, v.Verify(context.Background(), "Bearer token"))
	require.NoError(t, v.Verify(context.Background(), "Bearer token"))
	assert.EqualValues(t, 2, calls.Load())
}

func TestVerify_EndpointUnreachable(t *testing.T) {
	t.Parallel()

	v := New("http://127.0.0.1:1", 0)
	assert.Error(t, v.Verify(context.Background(), "Bearer token"))
}
