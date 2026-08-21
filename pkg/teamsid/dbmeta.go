package teamsid

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Bridgev2 metadata types for mautrix-teams.
//
// These are stored in the bridgev2 database as JSON blobs and must remain
// backward-compatible. Keep fields optional and additive.

type PortalMetadata struct {
	// Intentionally empty for now.
}

type GhostMetadata struct {
	// Intentionally empty for now.
}

type MessageMetadata struct {
	// Intentionally empty for now.
}

type ReactionMetadata struct {
	// Intentionally empty for now.
}

// UserLoginMetadata is persisted in bridgev2's user_login.metadata JSON column.
//
// It stores enough information to (re-)acquire a Teams skypetoken without redoing the full interactive login flow.
type UserLoginMetadata struct {
	RefreshToken         string `json:"refresh_token,omitempty"`
	AccessTokenExpiresAt int64  `json:"access_token_expires_at,omitempty"`
	// OAuthClientID identifies the public client that issued RefreshToken.
	// Empty means the legacy Teams web SPA client for backwards compatibility.
	OAuthClientID string `json:"oauth_client_id,omitempty"`

	SkypeToken          string `json:"skype_token,omitempty"`
	SkypeTokenExpiresAt int64  `json:"skype_token_expires_at,omitempty"`
	GraphAccessToken    string `json:"graph_access_token,omitempty"`
	GraphExpiresAt      int64  `json:"graph_expires_at,omitempty"`
	TeamsUserID         string `json:"teams_user_id,omitempty"`
}

const graphTokenExpirySkew = 60 * time.Second

var (
	ErrGraphAccessTokenMissing = errors.New("missing graph access token")
	ErrGraphAccessTokenExpired = errors.New("graph access token expired")
)

func (m *UserLoginMetadata) GraphTokenValid(now time.Time) bool {
	if m == nil || strings.TrimSpace(m.GraphAccessToken) == "" || m.GraphExpiresAt == 0 {
		return false
	}
	expiresAt := time.Unix(m.GraphExpiresAt, 0).UTC()
	return now.UTC().Add(graphTokenExpirySkew).Before(expiresAt)
}

func (m *UserLoginMetadata) GetGraphAccessToken() (string, error) {
	if m == nil || strings.TrimSpace(m.GraphAccessToken) == "" {
		return "", ErrGraphAccessTokenMissing
	}
	if !m.GraphTokenValid(time.Now().UTC()) {
		expiresAt := time.Unix(m.GraphExpiresAt, 0).UTC().Format(time.RFC3339)
		return "", fmt.Errorf("%w (expires_at=%s)", ErrGraphAccessTokenExpired, expiresAt)
	}
	return strings.TrimSpace(m.GraphAccessToken), nil
}
