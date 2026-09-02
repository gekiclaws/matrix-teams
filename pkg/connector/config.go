package connector

import (
	_ "embed"
	"strings"

	up "go.mau.fi/util/configupgrade"
)

//go:embed example-config.yaml
var ExampleConfig string

type TeamsConfig struct {
	// Legacy OAuth client ID fallback for logins created before OAuthClientID was
	// persisted in per-login metadata. New device-code logins ignore this field.
	ClientID string `yaml:"client_id"`
	// OAuthTokenEndpoint overrides the refresh-token endpoint for legacy or
	// externally provisioned organizational logins.
	OAuthTokenEndpoint string `yaml:"oauth_token_endpoint"`
	// SkypeTokenEndpoint overrides the access-token to Skype-token exchange
	// endpoint. Organizational Teams commonly uses the authsvc endpoint on
	// teams.microsoft.com rather than the consumer endpoint on teams.live.com.
	SkypeTokenEndpoint string `yaml:"skype_token_endpoint"`
	// OAuthRedirectURI controls the Origin header on legacy web-client refresh
	// grants. Leave empty to retain the consumer default.
	OAuthRedirectURI string `yaml:"oauth_redirect_uri"`
	// SkypeRefreshScopes replaces the consumer MBI refresh scopes for an
	// organizational login, for example an api.spaces.skype.com scope.
	SkypeRefreshScopes string `yaml:"skype_refresh_scopes"`
}

func upgradeConfig(helper up.Helper) {
	helper.Copy(up.Str, "client_id")
	helper.Copy(up.Str, "oauth_token_endpoint")
	helper.Copy(up.Str, "skype_token_endpoint")
	helper.Copy(up.Str, "oauth_redirect_uri")
	helper.Copy(up.Str, "skype_refresh_scopes")
}

func (c *TeamsConfig) parsedSkypeRefreshScopes() []string {
	if c == nil {
		return nil
	}
	return strings.Fields(c.SkypeRefreshScopes)
}

func (t *TeamsConnector) GetConfig() (string, any, up.Upgrader) {
	return ExampleConfig, &t.Config, up.SimpleUpgrader(upgradeConfig)
}
