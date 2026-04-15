package gatewayauth

import (
	"context"
	"errors"

	"github.com/dmathieu/gatewayauth/internal/verifier"
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
	verifier *verifier.Verifier
	component.StartFunc
	component.ShutdownFunc
}

func newExtension(cfg *Config) *gatewayAuth {
	return &gatewayAuth{
		verifier: verifier.New(cfg.Endpoint, cfg.CacheTTL, cfg.CacheSize),
	}
}

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
