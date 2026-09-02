package connector

import (
	"strings"

	"go.mau.fi/mautrix-teams/internal/teams/auth"
)

func (c *TeamsClient) newRefreshAuthClient() *auth.Client {
	client := auth.NewClient(nil)
	hasPersistedClientID := false
	if c != nil && c.Meta != nil {
		if clientID := strings.TrimSpace(c.Meta.OAuthClientID); clientID != "" {
			client.ClientID = clientID
			hasPersistedClientID = true
			if clientID == auth.TeamsPersonalClientID {
				// Native/public-client refresh grants must not carry the Teams web
				// SPA Origin header used by legacy Teams Web-issued logins.
				client.RedirectURI = ""
				client.TokenEndpoint = auth.TeamsPersonalTokenURL
				return client
			}
		}
	}
	if c != nil && c.Main != nil {
		if clientID := strings.TrimSpace(c.Main.Config.ClientID); clientID != "" && !hasPersistedClientID {
			client.ClientID = clientID
		}
		if endpoint := strings.TrimSpace(c.Main.Config.OAuthTokenEndpoint); endpoint != "" {
			client.TokenEndpoint = endpoint
		}
		if endpoint := strings.TrimSpace(c.Main.Config.SkypeTokenEndpoint); endpoint != "" {
			client.SkypeTokenEndpoint = endpoint
		}
		if redirectURI := strings.TrimSpace(c.Main.Config.OAuthRedirectURI); redirectURI != "" {
			client.RedirectURI = redirectURI
		}
	}
	return client
}

func (c *TeamsClient) skypeRefreshScopes() []string {
	if c != nil && c.Meta != nil && strings.TrimSpace(c.Meta.OAuthClientID) == auth.TeamsPersonalClientID {
		return strings.Fields(auth.TeamsPersonalScope)
	}
	if c != nil && c.Main != nil {
		if configured := c.Main.Config.parsedSkypeRefreshScopes(); len(configured) > 0 {
			return configured
		}
	}
	return []string{mbiRefreshScope, "offline_access"}
}
