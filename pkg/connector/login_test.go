package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"maunium.net/go/mautrix/bridgev2"

	"go.mau.fi/mautrix-teams/internal/teams/auth"
)

func TestDeviceCodeLoginFlowIsPreferred(t *testing.T) {
	connector := &TeamsConnector{}
	flows := connector.GetLoginFlows()
	if len(flows) != 1 || flows[0].ID != FlowIDDeviceCode {
		t.Fatalf("unexpected login flows: %+v", flows)
	}
	process, err := connector.CreateLogin(context.Background(), &bridgev2.User{}, FlowIDDeviceCode)
	if err != nil {
		t.Fatalf("create device code login: %v", err)
	}
	if _, ok := process.(*DeviceCodeLogin); !ok {
		t.Fatalf("expected *DeviceCodeLogin, got %T", process)
	}
}

func TestDeviceCodeLoginStartDisplaysChallenge(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"device_code":"secret","user_code":"ABCD-EFGH","verification_uri":"https://microsoft.com/devicelogin","expires_in":900,"interval":5}`))
	}))
	defer server.Close()

	originalFactory := newDeviceCodeClient
	newDeviceCodeClient = func() *auth.DeviceCodeClient {
		client := auth.NewDeviceCodeClient()
		client.HTTP = server.Client()
		client.DeviceCodeEndpoint = server.URL
		return client
	}
	defer func() { newDeviceCodeClient = originalFactory }()

	login := &DeviceCodeLogin{Main: &TeamsConnector{}, User: &bridgev2.User{}}
	step, err := login.Start(context.Background())
	if err != nil {
		t.Fatalf("start device code login: %v", err)
	}
	if step.Type != bridgev2.LoginStepTypeDisplayAndWait || step.DisplayAndWaitParams == nil {
		t.Fatalf("unexpected step: %+v", step)
	}
	if step.DisplayAndWaitParams.Type != bridgev2.LoginDisplayTypeCode || step.DisplayAndWaitParams.Data != "ABCD-EFGH" {
		t.Fatalf("unexpected display challenge: %+v", step.DisplayAndWaitParams)
	}
	if !strings.Contains(step.Instructions, "https://microsoft.com/devicelogin") {
		t.Fatalf("instructions missing verification URI: %q", step.Instructions)
	}
}

func TestPersonalDeviceCodeTokenIsRefreshedBeforeSkypeExchange(t *testing.T) {
	var refreshRequests, skypeRequests int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			refreshRequests++
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse refresh form: %v", err)
			}
			if got := r.Form.Get("grant_type"); got != "refresh_token" {
				t.Errorf("unexpected grant type: %q", got)
			}
			if got := r.Form.Get("refresh_token"); got != "device-refresh" {
				t.Errorf("unexpected refresh token: %q", got)
			}
			if got := r.Form.Get("scope"); got != auth.TeamsPersonalScope {
				t.Errorf("unexpected scope: %q", got)
			}
			if got := r.Header.Get("Origin"); got != "" {
				t.Errorf("personal native refresh sent Origin %q", got)
			}
			_, _ = w.Write([]byte(`{"access_token":"mbi-access","refresh_token":"rotated-refresh","expires_in":3600}`))
		case "/skype":
			skypeRequests++
			if got := r.Header.Get("Authorization"); got != "Bearer mbi-access" {
				t.Errorf("Skype exchange used %q", got)
			}
			_, _ = w.Write([]byte(`{"skypeToken":{"skypetoken":"skype-token","expiresIn":600,"skypeid":"live:test"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := auth.NewClient(nil)
	client.HTTP = server.Client()
	client.ClientID = auth.TeamsPersonalClientID
	client.TokenEndpoint = server.URL + "/token"
	client.SkypeTokenEndpoint = server.URL + "/skype"
	client.RedirectURI = ""
	client.Scopes = strings.Fields(auth.TeamsPersonalScope)
	state, skypeToken, _, skypeID, err := acquirePersonalTeamsSkypeToken(context.Background(), client, "device-refresh")
	if err != nil {
		t.Fatalf("bootstrap personal Teams token: %v", err)
	}
	if refreshRequests != 1 || skypeRequests != 1 {
		t.Fatalf("unexpected request counts: refresh=%d skype=%d", refreshRequests, skypeRequests)
	}
	if state.RefreshToken != "rotated-refresh" || skypeToken != "skype-token" || skypeID != "live:test" {
		t.Fatalf("unexpected result: state=%+v skypeToken=%q skypeID=%q", state, skypeToken, skypeID)
	}
}
