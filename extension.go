package gatewayauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dmathieu/gatewayauth/internal/authcache"
	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension/extensionauth"
)

// compile-time interface checks
var (
	_ extensionauth.Server = (*gatewayAuth)(nil)
	_ client.AuthData      = (*authData)(nil)
)

type gatewayAuth struct {
	cfg    *Config
	client *http.Client
	cache  *authcache.Cache
	component.StartFunc
	component.ShutdownFunc
}

func newExtension(cfg *Config) *gatewayAuth {
	return &gatewayAuth{
		cfg:    cfg,
		client: &http.Client{Timeout: 5 * time.Second},
		cache:  authcache.New(cfg.CacheTTL),
	}
}

// Authenticate implements extensionauth.Server. It forwards the Authorization
// header to the configured endpoint. A 2xx response grants access; any other
// response or error rejects the request. Results are cached for CacheTTL,
// except for 5xx responses which are never cached.
func (g *gatewayAuth) Authenticate(ctx context.Context, headers map[string][]string) (context.Context, error) {
	var authHeader string
	for _, v := range headers["Authorization"] {
		authHeader = v
		break
	}
	if authHeader == "" {
		return ctx, errors.New("missing Authorization header")
	}

	if cachedErr, ok := g.cache.Get(authHeader); ok {
		return g.buildContext(ctx, authHeader, cachedErr)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.cfg.Endpoint, nil)
	if err != nil {
		return ctx, fmt.Errorf("creating auth request: %w", err)
	}
	req.Header.Set("Authorization", authHeader)

	resp, err := g.client.Do(req)
	if err != nil {
		return ctx, fmt.Errorf("calling auth endpoint: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // body is empty for auth-check responses

	var authErr error
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		authErr = fmt.Errorf("auth endpoint returned status %d", resp.StatusCode)
	}

	// Do not cache 5xx: those are service errors, not definitive auth decisions.
	if resp.StatusCode < 500 {
		g.cache.Set(authHeader, authErr)
	}

	return g.buildContext(ctx, authHeader, authErr)
}

// buildContext attaches auth data to ctx on success, or returns the error.
func (g *gatewayAuth) buildContext(ctx context.Context, authHeader string, authErr error) (context.Context, error) {
	if authErr != nil {
		return ctx, authErr
	}
	cl := client.FromContext(ctx)
	cl.Auth = &authData{raw: authHeader}
	return client.NewContext(ctx, cl), nil
}

// authData implements client.AuthData, exposing the raw Authorization header
// value so downstream components can inspect it if needed.
type authData struct {
	raw string
}

// GetAttribute returns the value for the given attribute name.
func (a *authData) GetAttribute(name string) any {
	if name == "authorization" {
		return a.raw
	}
	return nil
}

// GetAttributeNames returns the list of attribute names available on this AuthData.
func (a *authData) GetAttributeNames() []string {
	return []string{"authorization"}
}
