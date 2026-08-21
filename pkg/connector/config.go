package connector

import (
	_ "embed"

	up "go.mau.fi/util/configupgrade"
)

//go:embed example-config.yaml
var ExampleConfig string

type TeamsConfig struct {
	// Legacy OAuth client ID fallback for logins created before OAuthClientID was
	// persisted in per-login metadata. New device-code logins ignore this field.
	ClientID string `yaml:"client_id"`
}

func upgradeConfig(helper up.Helper) {
	helper.Copy(up.Str, "client_id")
}

func (t *TeamsConnector) GetConfig() (string, any, up.Upgrader) {
	return ExampleConfig, &t.Config, up.SimpleUpgrader(upgradeConfig)
}
