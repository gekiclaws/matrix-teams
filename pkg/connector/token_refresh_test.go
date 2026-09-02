package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.mau.fi/mautrix-teams/internal/teams/auth"
	"go.mau.fi/mautrix-teams/pkg/teamsid"
)

func TestNewRefreshAuthClientUsesIssuingClient(t *testing.T) {
	client := (&TeamsClient{
		Main: &TeamsConnector{Config: TeamsConfig{ClientID: "legacy-config-client"}},
		Meta: &teamsid.UserLoginMetadata{OAuthClientID: auth.TeamsPersonalClientID},
	}).newRefreshAuthClient()
	if client.ClientID != auth.TeamsPersonalClientID {
		t.Fatalf("expected issuing client ID, got %q", client.ClientID)
	}
	if client.RedirectURI != "" {
		t.Fatalf("native refresh client must not send a web redirect origin, got %q", client.RedirectURI)
	}
	if client.TokenEndpoint != auth.TeamsPersonalTokenURL {
		t.Fatalf("unexpected personal refresh endpoint: %q", client.TokenEndpoint)
	}
}

func TestNativeRefreshDoesNotSendWebOrigin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			t.Fatalf("native refresh must not send Origin, got %q", origin)
		}
		_, _ = w.Write([]byte(`{"access_token":"access","refresh_token":"rotated","expires_in":3600}`))
	}))
	defer server.Close()

	client := (&TeamsClient{Meta: &teamsid.UserLoginMetadata{OAuthClientID: auth.TeamsPersonalClientID}}).newRefreshAuthClient()
	client.HTTP = server.Client()
	client.TokenEndpoint = server.URL
	client.Scopes = (&TeamsClient{Meta: &teamsid.UserLoginMetadata{OAuthClientID: auth.TeamsPersonalClientID}}).skypeRefreshScopes()
	if _, err := client.RefreshAccessToken(context.Background(), "refresh"); err != nil {
		t.Fatalf("refresh native token: %v", err)
	}
}

func TestNewRefreshAuthClientKeepsLegacyConfigFallback(t *testing.T) {
	client := (&TeamsClient{
		Main: &TeamsConnector{Config: TeamsConfig{
			ClientID:           "legacy-config-client",
			OAuthTokenEndpoint: "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
			SkypeTokenEndpoint: "https://teams.microsoft.com/api/authsvc/v1.0/authz",
			OAuthRedirectURI:   "https://teams.microsoft.com/go",
		}},
		Meta: &teamsid.UserLoginMetadata{},
	}).newRefreshAuthClient()
	if client.ClientID != "legacy-config-client" {
		t.Fatalf("expected configured legacy client ID, got %q", client.ClientID)
	}
	if client.TokenEndpoint != "https://login.microsoftonline.com/tenant/oauth2/v2.0/token" {
		t.Fatalf("unexpected organizational token endpoint: %q", client.TokenEndpoint)
	}
	if client.SkypeTokenEndpoint != "https://teams.microsoft.com/api/authsvc/v1.0/authz" {
		t.Fatalf("unexpected organizational Skype endpoint: %q", client.SkypeTokenEndpoint)
	}
	if client.RedirectURI != "https://teams.microsoft.com/go" {
		t.Fatalf("unexpected organizational redirect URI: %q", client.RedirectURI)
	}
}

func TestSkypeRefreshScopesFollowIssuingClient(t *testing.T) {
	native := (&TeamsClient{Meta: &teamsid.UserLoginMetadata{OAuthClientID: auth.TeamsPersonalClientID}}).skypeRefreshScopes()
	if len(native) != 4 || native[0] != "service::api.fl.spaces.skype.com::MBI_SSL" {
		t.Fatalf("unexpected native scopes: %v", native)
	}
	legacy := (&TeamsClient{Meta: &teamsid.UserLoginMetadata{}}).skypeRefreshScopes()
	if len(legacy) != 2 || legacy[0] != mbiRefreshScope {
		t.Fatalf("unexpected legacy scopes: %v", legacy)
	}
	enterprise := (&TeamsClient{
		Main: &TeamsConnector{Config: TeamsConfig{SkypeRefreshScopes: "https://api.spaces.skype.com/.default offline_access"}},
		Meta: &teamsid.UserLoginMetadata{},
	}).skypeRefreshScopes()
	if len(enterprise) != 2 || enterprise[0] != "https://api.spaces.skype.com/.default" {
		t.Fatalf("unexpected organizational scopes: %v", enterprise)
	}
}

func TestPersonalRefreshIgnoresEnterpriseOverrides(t *testing.T) {
	client := (&TeamsClient{
		Main: &TeamsConnector{Config: TeamsConfig{
			OAuthTokenEndpoint: "https://example.invalid/token",
			SkypeTokenEndpoint: "https://example.invalid/skype",
			OAuthRedirectURI:   "https://example.invalid/callback",
		}},
		Meta: &teamsid.UserLoginMetadata{OAuthClientID: auth.TeamsPersonalClientID},
	}).newRefreshAuthClient()
	if client.TokenEndpoint != auth.TeamsPersonalTokenURL || client.RedirectURI != "" {
		t.Fatalf("personal issuing profile was overridden: %+v", client)
	}
}

func TestEnterpriseRefreshKeepsIssuingClientAndUsesEndpointOverrides(t *testing.T) {
	client := (&TeamsClient{
		Main: &TeamsConnector{Config: TeamsConfig{
			ClientID:           "fallback-client",
			OAuthTokenEndpoint: "https://login.microsoftonline.com/tenant/oauth2/v2.0/token",
			SkypeTokenEndpoint: "https://teams.microsoft.com/api/authsvc/v1.0/authz",
		}},
		Meta: &teamsid.UserLoginMetadata{OAuthClientID: "issuing-enterprise-client"},
	}).newRefreshAuthClient()
	if client.ClientID != "issuing-enterprise-client" {
		t.Fatalf("issuing enterprise client was replaced: %q", client.ClientID)
	}
	if client.TokenEndpoint != "https://login.microsoftonline.com/tenant/oauth2/v2.0/token" ||
		client.SkypeTokenEndpoint != "https://teams.microsoft.com/api/authsvc/v1.0/authz" {
		t.Fatalf("enterprise endpoint overrides were not applied: %+v", client)
	}
}
