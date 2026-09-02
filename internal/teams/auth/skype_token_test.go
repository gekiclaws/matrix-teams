package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAcquireSkypeTokenSuccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer msal" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"skypeToken":{"skypetoken":"jwt","expiresIn":10,"skypeid":"live:tester"}}`))
	}))
	defer server.Close()

	client := NewClient(nil)
	client.SkypeTokenEndpoint = server.URL

	start := time.Now().UTC()
	result, err := client.AcquireSkypeToken(context.Background(), "msal")
	if err != nil {
		t.Fatalf("AcquireSkypeToken failed: %v", err)
	}
	if result.Token != "jwt" {
		t.Fatalf("unexpected token: %s", result.Token)
	}
	if result.SkypeID != "live:tester" {
		t.Fatalf("unexpected skype id: %s", result.SkypeID)
	}
	minExpiry := start.Add(10 * time.Second).Unix()
	maxExpiry := time.Now().UTC().Add(12 * time.Second).Unix()
	if result.ExpiresAt < minExpiry || result.ExpiresAt > maxExpiry {
		t.Fatalf("unexpected expiry: %d", result.ExpiresAt)
	}
}

func TestAcquireSkypeTokenMissingToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer msal" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"skypeToken":{"expiresIn":10}}`))
	}))
	defer server.Close()

	client := NewClient(nil)
	client.SkypeTokenEndpoint = server.URL

	_, err := client.AcquireSkypeToken(context.Background(), "msal")
	if err == nil {
		t.Fatalf("expected error for missing token")
	}
}

func TestAcquireSkypeTokenNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("nope"))
	}))
	defer server.Close()

	client := NewClient(nil)
	client.SkypeTokenEndpoint = server.URL

	_, err := client.AcquireSkypeToken(context.Background(), "msal")
	if err == nil {
		t.Fatalf("expected error for non-2xx")
	}
}

func TestAcquireSkypeTokenMissingAccessToken(t *testing.T) {
	client := NewClient(nil)
	client.SkypeTokenEndpoint = "https://example.invalid"

	_, err := client.AcquireSkypeToken(context.Background(), "")
	if err == nil {
		t.Fatalf("expected error for missing access token")
	}
}

func TestAcquireEnterpriseSkypeToken(t *testing.T) {
	claims := base64.RawURLEncoding.EncodeToString([]byte(`{"skypeid":"8:orgid:tenant-user"}`))
	jwt := "header." + claims + ".signature"
	now := time.Unix(1_700_000_000, 0).UTC()
	result, err := parseSkypeTokenResponse([]byte(`{"tokens":{"skypeToken":"`+jwt+`","expiresIn":600,"isBusinessTenant":true},"regionGtms":{"chatService":"https://amer.ng.msg.teams.microsoft.com","chatServiceAfd":"https://fallback.example","ams":"https://amer.ng.ams.teams.microsoft.com","amsV2":"https://fallback-ams.example"}}`), now)
	if err != nil {
		t.Fatalf("parse enterprise Skype token: %v", err)
	}
	if result.Token != jwt || result.SkypeID != "8:orgid:tenant-user" || !result.IsBusiness {
		t.Fatalf("unexpected enterprise result: %+v", result)
	}
	if result.ChatServiceURL != "https://amer.ng.msg.teams.microsoft.com" {
		t.Fatalf("unexpected chat service URL: %q", result.ChatServiceURL)
	}
	if result.AMSURL != "https://amer.ng.ams.teams.microsoft.com" {
		t.Fatalf("unexpected AMS URL: %q", result.AMSURL)
	}
	if result.ExpiresAt != now.Add(10*time.Minute).Unix() {
		t.Fatalf("unexpected expiry: %d", result.ExpiresAt)
	}
}

func TestHasValidSkypeToken(t *testing.T) {
	now := time.Now().UTC()
	state := &AuthState{
		SkypeToken:          "token",
		SkypeTokenExpiresAt: now.Add(70 * time.Second).Unix(),
	}
	if !state.HasValidSkypeToken(now) {
		t.Fatalf("expected token to be valid")
	}

	state.SkypeTokenExpiresAt = now.Add(50 * time.Second).Unix()
	if state.HasValidSkypeToken(now) {
		t.Fatalf("expected token to be invalid due to skew")
	}

	state.SkypeToken = ""
	if state.HasValidSkypeToken(now) {
		t.Fatalf("expected token to be invalid when empty")
	}
}
