package gatewayauth

import (
	"context"
	"time"

	"github.com/dmathieu/gatewayauth/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/extension"
)

// NewFactory creates a factory for the gateway Authenticator extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		createDefaultConfig,
		createExtension,
		metadata.ExtensionStability,
	)
}

func createDefaultConfig() component.Config {
	return &Config{
		CacheSize:        1000,
		HTTPClientConfig: confighttp.ClientConfig{Timeout: 5 * time.Second},
	}
}

func createExtension(_ context.Context, settings extension.Settings, cfg component.Config) (extension.Extension, error) {
	return newExtension(cfg.(*Config), settings), nil
}
