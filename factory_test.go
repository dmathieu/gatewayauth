package gatewayauth

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/extension/extensiontest"
)

func TestFactory_CreateDefaultConfig(t *testing.T) {
	cfg := createDefaultConfig()
	assert.Equal(t, &Config{}, cfg)
	assert.NoError(t, componenttest.CheckConfigStruct(cfg))
}

func TestFactory_Create(t *testing.T) {
	cfg := createDefaultConfig().(*Config)
	ext, err := createExtension(context.Background(), extensiontest.NewNopSettings(extensiontest.NopType), cfg)
	require.NoError(t, err)
	require.NotNil(t, ext)
}
