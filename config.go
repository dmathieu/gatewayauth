package gatewayauth

import (
	"errors"
	"fmt"
	"net/url"
	"time"

	"go.opentelemetry.io/collector/config/confighttp"
)

// Config defines the configuration for the gatewayauth extension.
type Config struct {
	// Endpoint is the URL used to validate incoming requests.
	// The Authorization header from the original request is forwarded to this
	// endpoint. A 2xx response grants access; any other response rejects it.
	Endpoint string `mapstructure:"endpoint"`

	// CacheTTL is how long auth results are cached. 5xx responses are never
	// cached regardless of this value. Defaults to 0 (no caching).
	CacheTTL time.Duration `mapstructure:"cache_ttl"`

	// CacheSize is the maximum number of entries in the auth result cache.
	// Only relevant when CacheTTL is non-zero. Defaults to 1000.
	CacheSize int `mapstructure:"cache_size"`

	// HTTPClientConfig configures the HTTP client used to call the auth endpoint.
	HTTPClientConfig confighttp.ClientConfig `mapstructure:"http_client"`

	// prevent unkeyed literal initialization
	_ struct{}
}

// Validate checks that the configuration is valid.
func (cfg *Config) Validate() error {
	if cfg.Endpoint == "" {
		return errors.New("endpoint must not be empty")
	}
	if _, err := url.ParseRequestURI(cfg.Endpoint); err != nil {
		return fmt.Errorf("endpoint is not a valid URL: %w", err)
	}
	if cfg.CacheTTL > 0 && cfg.CacheSize <= 0 {
		return errors.New("cache_size must be greater than 0 when cache_ttl is set")
	}
	return nil
}
