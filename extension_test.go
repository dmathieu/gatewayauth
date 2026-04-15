package gatewayauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension/extensiontest"
)

func TestAuthenticate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		headers      map[string][]string
		serverStatus int
		wantErr      bool
	}{
		{
			name:    "missing Authorization header",
			headers: map[string][]string{},
			wantErr: true,
		},
		{
			name:         "endpoint returns 200",
			headers:      map[string][]string{"Authorization": {"Bearer token123"}},
			serverStatus: http.StatusOK,
		},
		{
			name:         "endpoint returns 401",
			headers:      map[string][]string{"Authorization": {"Bearer bad"}},
			serverStatus: http.StatusUnauthorized,
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

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.serverStatus)
			}))
			t.Cleanup(srv.Close)

			cfg := createDefaultConfig().(*Config)
			cfg.Endpoint = srv.URL
			cfg.CacheTTL = time.Minute

			ext := newExtension(cfg, extensiontest.NewNopSettings(extensiontest.NopType))
			require.NoError(t, ext.Start(context.Background(), componenttest.NewNopHost()))
			t.Cleanup(func() { assert.NoError(t, ext.Shutdown(context.Background())) })

			ctx, err := ext.Authenticate(context.Background(), tt.headers)

			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			cl := client.FromContext(ctx)
			require.NotNil(t, cl.Auth)
			assert.Equal(t, "Bearer token123", cl.Auth.GetAttribute("authorization"))
			assert.Equal(t, []string{"authorization"}, cl.Auth.GetAttributeNames())
		})
	}
}
