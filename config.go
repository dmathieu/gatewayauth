package gatewayauth

import (
	"errors"
	"fmt"
	"net/url"
	"time"
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
	return nil
}
