package gatewayauth

import (
	"context"
	"errors"

	"github.com/dmathieu/gatewayauth/internal/authcache"
	"github.com/dmathieu/gatewayauth/internal/verifier"
	"go.opentelemetry.io/collector/client"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensionauth"
)

// compile-time interface checks
var (
	_ extensionauth.Server = (*gatewayAuth)(nil)
	_ client.AuthData      = (*authData)(nil)
)

type gatewayAuth struct {
	cfg      *Config
	settings extension.Settings
	verifier *verifier.Verifier
}

func newExtension(cfg *Config, settings extension.Settings) *gatewayAuth {
	return &gatewayAuth{cfg: cfg, settings: settings}
}

// Start creates the HTTP client via confighttp and initialises the verifier.
func (g *gatewayAuth) Start(ctx context.Context, host component.Host) error {
	httpClient, err := g.cfg.HTTPClientConfig.ToClient(ctx, host.GetExtensions(), g.settings.TelemetrySettings)
	if err != nil {
		return err
	}

	var cache *authcache.Cache
	if g.cfg.CacheTTL > 0 {
		cache = authcache.New(g.cfg.CacheTTL, g.cfg.CacheSize)
	}

	g.verifier = verifier.New(g.cfg.Endpoint, httpClient, cache)
	return nil
}

// Shutdown implements component.Component.
func (g *gatewayAuth) Shutdown(_ context.Context) error { return nil }

// Authenticate implements extensionauth.Server. It extracts the Authorization
// header and delegates to the verifier. On success the header value is attached
// to the context as auth data.
func (g *gatewayAuth) Authenticate(ctx context.Context, headers map[string][]string) (context.Context, error) {
	var authHeader string
	for _, v := range headers["Authorization"] {
		authHeader = v
		break
	}
	if authHeader == "" {
		return ctx, errors.New("missing Authorization header")
	}

	if err := g.verifier.Verify(ctx, authHeader); err != nil {
		return ctx, err
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
