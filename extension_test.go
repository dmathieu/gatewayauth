package gatewayauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/client"
)

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		headers        map[string][]string
		serverStatus   int
		serverFunc     http.HandlerFunc
		wantErr        bool
		wantAuthHeader string
	}{
		{
			name:         "missing Authorization header",
			headers:      map[string][]string{},
			wantErr:      true,
		},
		{
			name:           "endpoint returns 200",
			headers:        map[string][]string{"Authorization": {"Bearer token123"}},
			serverStatus:   http.StatusOK,
			wantAuthHeader: "Bearer token123",
		},
		{
			name:         "endpoint returns 401",
			headers:      map[string][]string{"Authorization": {"Bearer bad"}},
			serverStatus: http.StatusUnauthorized,
			wantErr:      true,
		},
		{
			name:         "endpoint returns 403",
			headers:      map[string][]string{"Authorization": {"Bearer forbidden"}},
			serverStatus: http.StatusForbidden,
			wantErr:      true,
		},
		{
			name:         "endpoint returns 500",
			headers:      map[string][]string{"Authorization": {"Bearer token"}},
			serverStatus: http.StatusInternalServerError,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var receivedAuthHeader string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				receivedAuthHeader = r.Header.Get("Authorization")
				w.WriteHeader(tt.serverStatus)
			}))
			t.Cleanup(srv.Close)

			ext := newExtension(&Config{Endpoint: srv.URL})
			ctx, err := ext.Authenticate(context.Background(), tt.headers)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantAuthHeader, receivedAuthHeader)

			cl := client.FromContext(ctx)
			require.NotNil(t, cl.Auth)
			assert.Equal(t, tt.wantAuthHeader, cl.Auth.GetAttribute("authorization"))
			assert.Equal(t, []string{"authorization"}, cl.Auth.GetAttributeNames())
		})
	}
}

func TestAuthenticate_EndpointUnreachable(t *testing.T) {
	t.Parallel()

	ext := newExtension(&Config{Endpoint: "http://127.0.0.1:1"})
	_, err := ext.Authenticate(context.Background(), map[string][]string{
		"Authorization": {"Bearer token"},
	})
	assert.Error(t, err)
}

func TestAuthenticate_CachesSuccessAndDenial(t *testing.T) {
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

	ext := newExtension(&Config{Endpoint: srv.URL, CacheTTL: time.Minute})
	headers := map[string][]string{"Authorization": {"Bearer good"}}

	// First call hits the endpoint.
	_, err := ext.Authenticate(context.Background(), headers)
	require.NoError(t, err)
	assert.EqualValues(t, 1, calls.Load())

	// Second call should be served from cache.
	_, err = ext.Authenticate(context.Background(), headers)
	require.NoError(t, err)
	assert.EqualValues(t, 1, calls.Load())

	// Denied tokens are also cached.
	badHeaders := map[string][]string{"Authorization": {"Bearer bad"}}
	_, err = ext.Authenticate(context.Background(), badHeaders)
	assert.Error(t, err)
	assert.EqualValues(t, 2, calls.Load())

	_, err = ext.Authenticate(context.Background(), badHeaders)
	assert.Error(t, err)
	assert.EqualValues(t, 2, calls.Load())
}

func TestAuthenticate_DoesNotCache5xx(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	ext := newExtension(&Config{Endpoint: srv.URL, CacheTTL: time.Minute})
	headers := map[string][]string{"Authorization": {"Bearer token"}}

	_, err := ext.Authenticate(context.Background(), headers)
	assert.Error(t, err)
	assert.EqualValues(t, 1, calls.Load())

	// Should hit the endpoint again — 5xx must not be cached.
	_, err = ext.Authenticate(context.Background(), headers)
	assert.Error(t, err)
	assert.EqualValues(t, 2, calls.Load())
}
