package connector

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.mau.fi/mautrix-teams/internal/teams/auth"
	"go.mau.fi/mautrix-teams/pkg/teamsid"

	"maunium.net/go/mautrix/bridgev2"
)

const mbiRefreshScope = "service::api.fl.spaces.skype.com::MBI_SSL"
const graphFilesReadWriteScope = "https://graph.microsoft.com/Files.ReadWrite"

var newAuthClient = auth.NewClient

// ExtractTeamsLoginMetadataFromLocalStorage parses the MSAL localStorage payload
// and exchanges its access token for a Teams skypetoken.
func ExtractTeamsLoginMetadataFromLocalStorage(ctx context.Context, rawStorage, clientID string) (*teamsid.UserLoginMetadata, error) {
	state, err := auth.ExtractTokensFromMSALLocalStorage(rawStorage, clientID)
	if err != nil {
		return nil, bridgev2.RespError{ErrCode: "FI.MAU.TEAMS_INVALID_STORAGE", Err: fmt.Sprintf("Failed to extract tokens: %v", err), StatusCode: http.StatusBadRequest}
	}
	authClient := newAuthClient(nil)
	if id := strings.TrimSpace(clientID); id != "" {
		authClient.ClientID = id
	}
	accessToken := strings.TrimSpace(state.AccessToken)
	directSkypeToken := strings.TrimSpace(state.SkypeToken)
	directTeamsUserID := auth.NormalizeTeamsUserID(state.TeamsUserID)
	useDirectSkypeToken := directSkypeToken != "" && directTeamsUserID != "" &&
		time.Now().UTC().Add(auth.SkypeTokenExpirySkew).Before(time.Unix(state.SkypeTokenExpiresAt, 0).UTC())
	if !useDirectSkypeToken && accessToken == "" {
		refreshToken := strings.TrimSpace(state.RefreshToken)
		if refreshToken == "" {
			return nil, bridgev2.RespError{ErrCode: "FI.MAU.TEAMS_MISSING_ACCESS_TOKEN", Err: "Access token missing from extracted state", StatusCode: http.StatusBadRequest}
		}
		refreshed, refreshErr := refreshAccessTokenForSkypeScope(ctx, authClient, refreshToken)
		if refreshErr != nil {
			return nil, bridgev2.RespError{ErrCode: "FI.MAU.TEAMS_MISSING_ACCESS_TOKEN", Err: fmt.Sprintf("Access token missing from localStorage and refresh failed: %v", refreshErr), StatusCode: http.StatusBadRequest}
		}
		accessToken = strings.TrimSpace(refreshed.AccessToken)
		if accessToken == "" {
			return nil, bridgev2.RespError{ErrCode: "FI.MAU.TEAMS_MISSING_ACCESS_TOKEN", Err: "Access token missing after refresh-token exchange", StatusCode: http.StatusBadRequest}
		}
		if rt := strings.TrimSpace(refreshed.RefreshToken); rt != "" {
			state.RefreshToken = rt
		}
		if refreshed.ExpiresAtUnix != 0 {
			state.ExpiresAtUnix = refreshed.ExpiresAtUnix
		}
		if token := strings.TrimSpace(refreshed.GraphAccessToken); token != "" {
			state.GraphAccessToken = token
			state.GraphExpiresAt = refreshed.GraphExpiresAt
		}
	}
	if strings.TrimSpace(state.GraphAccessToken) == "" {
		refreshToken := strings.TrimSpace(state.RefreshToken)
		if refreshToken != "" {
			graphState, graphErr := refreshAccessTokenForGraphScope(ctx, authClient, refreshToken)
			if graphErr == nil {
				if token := strings.TrimSpace(graphState.GraphAccessToken); token != "" {
					state.GraphAccessToken = token
					state.GraphExpiresAt = graphState.GraphExpiresAt
				}
				if rt := strings.TrimSpace(graphState.RefreshToken); rt != "" {
					state.RefreshToken = rt
				}
			}
		}
	}

	token := directSkypeToken
	expiresAt := state.SkypeTokenExpiresAt
	teamsUserID := directTeamsUserID
	if !useDirectSkypeToken {
		var skypeID string
		token, expiresAt, skypeID, err = authClient.AcquireSkypeToken(ctx, accessToken)
		if err != nil {
			return nil, bridgev2.RespError{ErrCode: "FI.MAU.TEAMS_SKYPETOKEN_FAILED", Err: fmt.Sprintf("Failed to acquire skypetoken: %v", err), StatusCode: http.StatusBadRequest}
		}
		teamsUserID = auth.NormalizeTeamsUserID(skypeID)
	}

	if teamsUserID == "" {
		return nil, bridgev2.RespError{ErrCode: "FI.MAU.TEAMS_MISSING_USER_ID", Err: "Teams user ID missing from skypetoken response", StatusCode: http.StatusBadRequest}
	}

	return &teamsid.UserLoginMetadata{
		RefreshToken:         state.RefreshToken,
		AccessTokenExpiresAt: state.ExpiresAtUnix,
		SkypeToken:           token,
		SkypeTokenExpiresAt:  expiresAt,
		GraphAccessToken:     strings.TrimSpace(state.GraphAccessToken),
		GraphExpiresAt:       state.GraphExpiresAt,
		TeamsUserID:          teamsUserID,
	}, nil
}

func refreshAccessTokenForSkypeScope(ctx context.Context, client *auth.Client, refreshToken string) (*auth.AuthState, error) {
	// Prefer requesting the Skype MBI scope explicitly for skypetoken bootstrap.
	retryClient := *client
	retryClient.Scopes = []string{mbiRefreshScope, "offline_access"}
	refreshed, err := retryClient.RefreshAccessToken(ctx, refreshToken)
	if err == nil {
		return refreshed, nil
	}

	// Fallback to default scopes for environments that don't accept MBI scope on refresh.
	fallbackClient := *client
	fallbackClient.Scopes = []string{"openid", "profile", "offline_access"}
	refreshed, fallbackErr := fallbackClient.RefreshAccessToken(ctx, refreshToken)
	if fallbackErr == nil {
		return refreshed, nil
	}

	return nil, fmt.Errorf("MBI scope refresh failed (%v); default scopes failed (%v)", err, fallbackErr)
}

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

func resolveClientID(main *TeamsConnector) string {
	if main != nil {
		if id := strings.TrimSpace(main.Config.ClientID); id != "" {
			return id
		}
	}
	return auth.NewClient(nil).ClientID
}
