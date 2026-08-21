package connector

import (
	"context"
	"fmt"

	"go.mau.fi/mautrix-teams/internal/teams/auth"
)

const mbiRefreshScope = "service::api.fl.spaces.skype.com::MBI_SSL"
const graphFilesReadWriteScope = "https://graph.microsoft.com/Files.ReadWrite"

var newAuthClient = auth.NewClient

func refreshAccessTokenForGraphScope(ctx context.Context, client *auth.Client, refreshToken string) (*auth.AuthState, error) {
	retryClient := *client
	retryClient.Scopes = []string{graphFilesReadWriteScope, "offline_access"}
	refreshed, err := retryClient.RefreshAccessToken(ctx, refreshToken)
	if err == nil {
		return refreshed, nil
	}

	fallbackClient := *client
	fallbackClient.Scopes = []string{"openid", "profile", "offline_access", graphFilesReadWriteScope}
	refreshed, fallbackErr := fallbackClient.RefreshAccessToken(ctx, refreshToken)
	if fallbackErr == nil {
		return refreshed, nil
	}

	return nil, fmt.Errorf("graph scope refresh failed (%v); fallback scopes failed (%v)", err, fallbackErr)
}
