package connector

import (
	"strings"

	"go.mau.fi/mautrix-teams/internal/teams/auth"
)

func (c *TeamsClient) newRefreshAuthClient() *auth.Client {
	client := auth.NewClient(nil)
	if c != nil && c.Meta != nil {
		if clientID := strings.TrimSpace(c.Meta.OAuthClientID); clientID != "" {
			client.ClientID = clientID
			if clientID == auth.TeamsPersonalClientID {
				// Native/public-client refresh grants must not carry the Teams web
				// SPA Origin header used by legacy Teams Web-issued logins.
				client.RedirectURI = ""
				client.TokenEndpoint = auth.TeamsPersonalTokenURL
			}
			return client
		}
	}
	if c != nil && c.Main != nil {
		if clientID := strings.TrimSpace(c.Main.Config.ClientID); clientID != "" {
			client.ClientID = clientID
		}
	}
	return client
}

func (c *TeamsClient) skypeRefreshScopes() []string {
	if c != nil && c.Meta != nil && strings.TrimSpace(c.Meta.OAuthClientID) == auth.TeamsPersonalClientID {
		return strings.Fields(auth.TeamsPersonalScope)
	}
	return []string{mbiRefreshScope, "offline_access"}
}
