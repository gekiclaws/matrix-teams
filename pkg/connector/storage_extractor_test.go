package connector

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"go.mau.fi/mautrix-teams/internal/teams/auth"
)

func TestExtractTeamsLoginMetadataFromLocalStorage_PersistsGraphToken(t *testing.T) {
	skypeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer mbi-access-token" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		_, _ = w.Write([]byte(`{"skypeToken":{"skypetoken":"skype-token","expiresIn":600,"skypeid":"live:tester"}}`))
	}))
	defer skypeServer.Close()

	origFactory := newAuthClient
	newAuthClient = func(store *auth.CookieStore) *auth.Client {
		client := auth.NewClient(store)
		client.SkypeTokenEndpoint = skypeServer.URL
		return client
	}
	defer func() {
		newAuthClient = origFactory
	}()

	storage := map[string]string{
		"msal.token.keys." + auth.NewClient(nil).ClientID: `{"refreshToken":["rt"],"idToken":["id"],"accessToken":["mbi","graph"]}`,
		"rt":    `{"secret":"refresh-token","expiresOn":"1700000000"}`,
		"id":    `{"secret":"id-token"}`,
		"mbi":   `{"secret":"mbi-access-token","expiresOn":"1700000100","target":"service::api.fl.spaces.skype.com::MBI_SSL"}`,
		"graph": `{"secret":"graph-access-token","expiresOn":"1700000200","target":"https://graph.microsoft.com/Files.ReadWrite User.Read"}`,
	}
	payload, err := json.Marshal(storage)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	meta, err := ExtractTeamsLoginMetadataFromLocalStorage(context.Background(), string(payload), auth.NewClient(nil).ClientID)
	if err != nil {
		t.Fatalf("unexpected extraction error: %v", err)
	}
	if meta.GraphAccessToken != "graph-access-token" {
		t.Fatalf("unexpected graph token: %s", meta.GraphAccessToken)
	}
	if meta.GraphExpiresAt != 1700000200 {
		t.Fatalf("unexpected graph expiry: %d", meta.GraphExpiresAt)
	}
	if meta.SkypeToken != "skype-token" {
		t.Fatalf("unexpected skype token: %s", meta.SkypeToken)
	}
	if meta.TeamsUserID != "8:live:tester" {
		t.Fatalf("unexpected teams user id: %s", meta.TeamsUserID)
	}
}

func TestExtractTeamsLoginMetadataFromLocalStorage_NoGraphTokenStillSucceeds(t *testing.T) {
	skypeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"skypeToken":{"skypetoken":"skype-token","expiresIn":600,"skypeid":"live:tester"}}`))
	}))
	defer skypeServer.Close()

	origFactory := newAuthClient
	newAuthClient = func(store *auth.CookieStore) *auth.Client {
		client := auth.NewClient(store)
		client.SkypeTokenEndpoint = skypeServer.URL
		return client
	}
	defer func() {
		newAuthClient = origFactory
	}()

	storage := map[string]string{
		"msal.token.keys." + auth.NewClient(nil).ClientID: `{"refreshToken":["rt"],"accessToken":["mbi"]}`,
		"rt":  `{"secret":"refresh-token","expiresOn":"1700000000"}`,
		"mbi": `{"secret":"mbi-access-token","expiresOn":"1700000100","target":"service::api.fl.spaces.skype.com::MBI_SSL"}`,
	}
	payload, err := json.Marshal(storage)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	meta, err := ExtractTeamsLoginMetadataFromLocalStorage(context.Background(), string(payload), auth.NewClient(nil).ClientID)
	if err != nil {
		t.Fatalf("unexpected extraction error: %v", err)
	}
	if meta.GraphAccessToken != "" {
		t.Fatalf("expected empty graph token, got %s", meta.GraphAccessToken)
	}
	if meta.GraphExpiresAt != 0 {
		t.Fatalf("expected empty graph expiry, got %d", meta.GraphExpiresAt)
	}
	if meta.SkypeToken != "skype-token" {
		t.Fatalf("unexpected skype token: %s", meta.SkypeToken)
	}
}

func TestExtractTeamsLoginMetadataFromLocalStorage_RefreshesGraphWhenMissingInStorage(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		scope := r.Form.Get("scope")
		switch {
		case scope == "service::api.fl.spaces.skype.com::MBI_SSL offline_access":
			_, _ = w.Write([]byte(`{"access_token":"mbi-from-refresh","refresh_token":"refresh-updated","expires_in":3600}`))
		case scope == "https://graph.microsoft.com/Files.ReadWrite offline_access":
			_, _ = w.Write([]byte(`{"access_token":"graph-from-refresh","refresh_token":"refresh-updated-2","expires_in":7200}`))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	defer tokenServer.Close()

	skypeServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer mbi-from-refresh" {
			t.Fatalf("unexpected authorization header: %s", got)
		}
		_, _ = w.Write([]byte(`{"skypeToken":{"skypetoken":"skype-token","expiresIn":600,"skypeid":"live:tester"}}`))
	}))
	defer skypeServer.Close()

	origFactory := newAuthClient
	newAuthClient = func(store *auth.CookieStore) *auth.Client {
		client := auth.NewClient(store)
		client.TokenEndpoint = tokenServer.URL
		client.SkypeTokenEndpoint = skypeServer.URL
		return client
	}
	defer func() {
		newAuthClient = origFactory
	}()

	storage := map[string]string{
		"msal.token.keys." + auth.NewClient(nil).ClientID: `{"refreshToken":["rt"],"accessToken":["openid-only"]}`,
		"rt":          `{"secret":"refresh-token","expiresOn":"1700000000"}`,
		"openid-only": `{"secret":"openid-token","expiresOn":"1700000100","target":"openid profile"}`,
	}
	payload, err := json.Marshal(storage)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	meta, err := ExtractTeamsLoginMetadataFromLocalStorage(context.Background(), string(payload), auth.NewClient(nil).ClientID)
	if err != nil {
		t.Fatalf("unexpected extraction error: %v", err)
	}
	if meta.GraphAccessToken != "graph-from-refresh" {
		t.Fatalf("unexpected graph token: %s", meta.GraphAccessToken)
	}
	if meta.GraphExpiresAt == 0 {
		t.Fatalf("expected graph expiry to be set")
	}
	if meta.RefreshToken != "refresh-updated-2" {
		t.Fatalf("unexpected refresh token: %s", meta.RefreshToken)
	}
	if meta.SkypeToken != "skype-token" {
		t.Fatalf("unexpected skype token: %s", meta.SkypeToken)
	}
}

func TestExtractTeamsLoginMetadataFromLocalStorage_UsesEncryptedCachedSkypeToken(t *testing.T) {
	baseKey := []byte("0123456789abcdef0123456789abcdef")
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Unix()
	storage := map[string]string{
		"tmp.auth.v1.GLOBAL.ExportedEncryptionKey.ExportedEncryptionKey": marshalTestJSON(t, map[string]any{
			"item": map[string]string{"exportedKey": base64.StdEncoding.EncodeToString(baseKey)},
		}),
		"tmp.auth.v1.live-user.Discover.SKYPE-TOKEN": encryptedTeamsAuthCacheValue(t, baseKey, "cached-skype-token", map[string]any{
			"expiration":  expiresAt * 1000,
			"userDetails": map[string]string{"id": "live:cached-user"},
		}),
	}

	origFactory := newAuthClient
	newAuthClient = func(store *auth.CookieStore) *auth.Client {
		client := auth.NewClient(store)
		client.SkypeTokenEndpoint = "http://127.0.0.1:1/should-not-be-called"
		return client
	}
	defer func() {
		newAuthClient = origFactory
	}()

	meta, err := ExtractTeamsLoginMetadataFromLocalStorage(context.Background(), marshalTestJSON(t, storage), auth.NewClient(nil).ClientID)
	if err != nil {
		t.Fatalf("unexpected extraction error: %v", err)
	}
	if meta.SkypeToken != "cached-skype-token" {
		t.Fatalf("unexpected Skype token: %q", meta.SkypeToken)
	}
	if meta.SkypeTokenExpiresAt != expiresAt {
		t.Fatalf("unexpected Skype token expiry: %d", meta.SkypeTokenExpiresAt)
	}
	if meta.TeamsUserID != "8:live:cached-user" {
		t.Fatalf("unexpected Teams user ID: %q", meta.TeamsUserID)
	}
}

func encryptedTeamsAuthCacheValue(t *testing.T, baseKey []byte, plaintext string, extra map[string]any) string {
	t.Helper()
	block, err := aes.NewCipher(baseKey)
	if err != nil {
		t.Fatalf("create test cipher: %v", err)
	}
	iv := []byte("0123456789abcdef")
	padding := block.BlockSize() - len(plaintext)%block.BlockSize()
	padded := make([]byte, len(plaintext)+padding)
	copy(padded, plaintext)
	for i := len(plaintext); i < len(padded); i++ {
		padded[i] = byte(padding)
	}
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	item := map[string]any{
		"encryptedToken": base64.StdEncoding.EncodeToString(ciphertext),
		"iv":             base64.StdEncoding.EncodeToString(iv),
	}
	for key, value := range extra {
		item[key] = value
	}
	return marshalTestJSON(t, map[string]any{"item": item})
}

func marshalTestJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal test JSON: %v", err)
	}
	return string(encoded)
}
