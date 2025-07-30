package gatewayauth

type Config struct {
	// prevent unkeyed literal initialization
	_ struct{}
}

func (cfg *Config) Validate() error {
	return nil
}
