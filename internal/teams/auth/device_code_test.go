package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDeviceCodeStartAndPoll(t *testing.T) {
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatalf("parse form: %v", err)
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			t.Fatalf("native device-code request must not send Origin, got %q", origin)
		}
		switch r.URL.Path {
		case "/devicecode":
			if r.Form.Get("client_id") != TeamsPersonalClientID {
				t.Fatalf("unexpected client id: %q", r.Form.Get("client_id"))
			}
			if r.Form.Get("resource") != TeamsPersonalResource {
				t.Fatalf("unexpected resource: %q", r.Form.Get("resource"))
			}
			if r.Form.Get("scope") != "" {
				t.Fatalf("legacy personal device-code request must not send v2 scope: %q", r.Form.Get("scope"))
			}
			_, _ = w.Write([]byte(`{"device_code":"device-secret","user_code":"ABCD-EFGH","verification_url":"https://login.microsoft.com/device","expires_in":"900","interval":"1"}`))
		case "/token":
			if r.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:device_code" {
				t.Fatalf("unexpected grant type: %q", r.Form.Get("grant_type"))
			}
			if r.Form.Get("code") != "device-secret" {
				t.Fatalf("unexpected device code: %q", r.Form.Get("code"))
			}
			if r.Form.Get("device_code") != "" {
				t.Fatalf("legacy personal poll must use code, got device_code=%q", r.Form.Get("device_code"))
			}
			if polls.Add(1) == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_, _ = w.Write([]byte(`{"access_token":"access","refresh_token":"refresh","id_token":"id","expires_in":"3600"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client := NewDeviceCodeClient()
	client.HTTP = server.Client()
	client.DeviceCodeEndpoint = server.URL + "/devicecode"
	client.TokenEndpoint = server.URL + "/token"

	challenge, err := client.Start(context.Background())
	if err != nil {
		t.Fatalf("start device code: %v", err)
	}
	if challenge.UserCode != "ABCD-EFGH" || challenge.DeviceCode != "device-secret" {
		t.Fatalf("unexpected challenge: %+v", challenge)
	}

	state, err := client.Poll(context.Background(), challenge.DeviceCode, time.Millisecond)
	if err != nil {
		t.Fatalf("poll device code: %v", err)
	}
	if state.AccessToken != "access" || state.RefreshToken != "refresh" || state.IDToken != "id" {
		t.Fatalf("unexpected auth state: %+v", state)
	}
	if state.ExpiresAtUnix <= time.Now().UTC().Unix() {
		t.Fatalf("expected future access token expiry, got %d", state.ExpiresAtUnix)
	}
}

func TestDeviceCodePollDeclined(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"authorization_declined","error_description":"no"}`))
	}))
	defer server.Close()

	client := NewDeviceCodeClient()
	client.HTTP = server.Client()
	client.TokenEndpoint = server.URL
	_, err := client.Poll(context.Background(), "device-secret", time.Millisecond)
	if !errors.Is(err, ErrDeviceCodeDeclined) {
		t.Fatalf("expected ErrDeviceCodeDeclined, got %v", err)
	}
}

func TestDeviceCodeStartRedactsLargeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(strings.Repeat("x", 500)))
	}))
	defer server.Close()

	client := NewDeviceCodeClient()
	client.HTTP = server.Client()
	client.DeviceCodeEndpoint = server.URL
	_, err := client.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "...(truncated)") || len(err.Error()) > 500 {
		t.Fatalf("expected truncated endpoint error, got %v", err)
	}
}
