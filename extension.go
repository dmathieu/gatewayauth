package gatewayauth

import "go.opentelemetry.io/collector/component"

func newExtension(cfg *Config) *gatewayAuth {
	return &gatewayAuth{}
}

type gatewayAuth struct {
	component.StartFunc
	component.ShutdownFunc
}
