package gatewayauth

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/dmathieu/gatewayauth/internal/metadata"
	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/config/confighttp"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap/confmaptest"
	"go.opentelemetry.io/collector/confmap/xconfmap"
)

func TestLoadConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id          component.ID
		expected    component.Config
		expectedErr bool
	}{
		{
			id:       component.NewID(metadata.Type),
			expected: &Config{
				Endpoint:         "https://auth.example.com/validate",
				CacheTTL:         5 * time.Minute,
				CacheSize:        1000,
				HTTPClientConfig: confighttp.ClientConfig{Timeout: 5 * time.Second},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.id.String(), func(t *testing.T) {
			cm, err := confmaptest.LoadConf(filepath.Join("testdata", "config.yaml"))
			require.NoError(t, err)

			factory := NewFactory()
			cfg := factory.CreateDefaultConfig()
			sub, err := cm.Sub(tt.id.String())
			require.NoError(t, err)
			require.NoError(t, sub.Unmarshal(cfg))

			if tt.expectedErr {
				assert.Error(t, xconfmap.Validate(cfg))
				return
			}
			assert.NoError(t, xconfmap.Validate(cfg))
			assert.Equal(t, tt.expected, cfg)
		})
	}
}

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid endpoint",
			cfg:  &Config{Endpoint: "https://auth.example.com/validate"},
		},
		{
			name:    "cache_ttl set but cache_size zero",
			cfg:     &Config{Endpoint: "https://auth.example.com/validate", CacheTTL: time.Minute},
			wantErr: true,
		},
		{
			name:    "empty endpoint",
			cfg:     &Config{},
			wantErr: true,
		},
		{
			name:    "invalid URL",
			cfg:     &Config{Endpoint: "not a url"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
