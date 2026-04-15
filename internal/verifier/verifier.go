// Package verifier checks authorization tokens against a remote endpoint,
// caching definitive outcomes to reduce upstream load.
package verifier

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/dmathieu/gatewayauth/internal/authcache"
)

// Verifier forwards an Authorization token to a configured endpoint and
// returns nil if access is granted. Results are cached for the configured TTL;
// 5xx responses are never cached because they indicate a service error rather
// than a definitive auth decision.
type Verifier struct {
	endpoint string
	client   *http.Client
	cache    *authcache.Cache
}

// New returns a Verifier that calls endpoint and caches results for ttl.
// When ttl is zero, results are never cached.
func New(endpoint string, ttl time.Duration) *Verifier {
	v := &Verifier{
		endpoint: endpoint,
		client:   &http.Client{Timeout: 5 * time.Second},
	}
	if ttl > 0 {
		v.cache = authcache.New(ttl)
	}
	return v
}

// Verify checks whether token is authorized. It returns nil on success and a
// non-nil error on denial or failure.
func (v *Verifier) Verify(ctx context.Context, token string) error {
	if v.cache != nil {
		if cached, ok := v.cache.Get(token); ok {
			return cached
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating auth request: %w", err)
	}
	req.Header.Set("Authorization", token)

	resp, err := v.client.Do(req)
	if err != nil {
		return fmt.Errorf("calling auth endpoint: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // body is empty for auth-check responses

	var authErr error
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		authErr = fmt.Errorf("auth endpoint returned status %d", resp.StatusCode)
	}

	// Do not cache 5xx: those are service errors, not definitive auth decisions.
	if v.cache != nil && resp.StatusCode < 500 {
		v.cache.Set(token, authErr)
	}

	return authErr
}
