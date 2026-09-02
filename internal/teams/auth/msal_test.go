package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestSelectMBIAccessToken(t *testing.T) {
	storage := map[string]string{
		"access1": `{"secret":"token-openid","expiresOn":"1700000000","target":"openid profile"}`,
		"access2": `{"secret":"token-mbi","expiresOn":"1700000100","target":"service::api.fl.spaces.skype.com::MBI_SSL"}`,
		"access3": `{"secret":"token-mbi-2","expiresOn":"1700000200","target":"service::api.fl.spaces.skype.com::MBI_SSL"}`,
	}
	keys := []string{"access1", "access2", "access3"}

	token, expiry := selectMBIAccessToken(storage, keys, "", nil)
	if token != "token-mbi-2" {
		t.Fatalf("unexpected token: %s", token)
	}
	if expiry != 1700000200 {
		t.Fatalf("unexpected expiry: %d", expiry)
	}
}

func TestSelectGraphAccessToken(t *testing.T) {
	storage := map[string]string{
		"access1": `{"secret":"token-openid","expiresOn":"1700000000","target":"openid profile"}`,
		"access2": `{"secret":"token-graph-1","expiresOn":"1700000100","target":"https://graph.microsoft.com/Files.ReadWrite User.Read"}`,
		"access3": `{"secret":"token-graph-2","expiresOn":"1700000200","target":"https://graph.microsoft.com/User.Read Files.ReadWrite"}`,
	}
	keys := []string{"access1", "access2", "access3"}

	token, expiry := selectGraphAccessToken(storage, keys, "", nil)
	if token != "token-graph-2" {
		t.Fatalf("unexpected token: %s", token)
	}
	if expiry != 1700000200 {
		t.Fatalf("unexpected expiry: %d", expiry)
	}
}

func TestSelectGraphAccessTokenMissing(t *testing.T) {
	storage := map[string]string{
		"access1": `{"secret":"token-openid","expiresOn":"1700000000","target":"openid profile"}`,
	}
	keys := []string{"access1"}

	token, expiry := selectGraphAccessToken(storage, keys, "", nil)
	if token != "" || expiry != 0 {
		t.Fatalf("expected no token, got %q with expiry %d", token, expiry)
	}
}

func TestSelectMBIAccessTokenMissing(t *testing.T) {
	storage := map[string]string{
		"access1": `{"secret":"token-openid","expiresOn":"1700000000","target":"openid profile"}`,
	}
	keys := []string{"access1"}

	token, expiry := selectMBIAccessToken(storage, keys, "", nil)
	if token != "" || expiry != 0 {
		t.Fatalf("expected no token, got %q with expiry %d", token, expiry)
	}
}

func TestExtractTokensUsesEnterpriseSkypeAPIAccessToken(t *testing.T) {
	t.Parallel()
	const clientID = "teams-web-client"
	refreshKey := "refresh"
	skypeKey := "skype"
	storage := map[string]string{
		"msal.token.keys." + clientID: `{"refreshToken":["` + refreshKey + `"],"accessToken":["` + skypeKey + `"]}`,
		refreshKey:                    `{"secret":"refresh-token","expiresOn":"1700000000"}`,
		skypeKey:                      `{"secret":"enterprise-access","expiresOn":"1700000300","target":"https://api.spaces.skype.com/.default"}`,
	}

	state, err := ExtractTokensFromMSALLocalStorage(mustJSON(t, storage), clientID)
	if err != nil {
		t.Fatalf("extract enterprise MSAL storage: %v", err)
	}
	if state.AccessToken != "enterprise-access" || state.ExpiresAtUnix != 1700000300 {
		t.Fatalf("unexpected enterprise access token state: %+v", state)
	}
}

func TestSelectSkypeAPIAccessTokenPrefersLatestExpiry(t *testing.T) {
	storage := map[string]string{
		"access1": `{"secret":"old","expiresOn":"1700000100","target":"https://api.spaces.skype.com/.default"}`,
		"access2": `{"secret":"new","expiresOn":"1700000200","target":"https://API.SPACES.SKYPE.COM/.default"}`,
		"access3": `{"secret":"graph","expiresOn":"1700000300","target":"https://graph.microsoft.com/User.Read"}`,
	}
	token, expiry := selectSkypeAPIAccessToken(storage, []string{"access1", "access2", "access3"}, "", nil)
	if token != "new" || expiry != 1700000200 {
		t.Fatalf("unexpected token=%q expiry=%d", token, expiry)
	}
}

func TestExtractTokensFromEncryptedMSALStorage(t *testing.T) {
	t.Parallel()
	baseKey := randomBytes(t, 32)
	const (
		clientID = "4b3e8f46-56d3-427f-b1e2-d239b2ea6bca"
		keyID    = "4d36b33d-5f4f-4f28-970f-7f28a2b7262e"
	)
	refreshKey := "msal.2|home|env|refreshtoken|" + clientID + "|||"
	mbiKey := "msal.2|home|env|accesstoken|" + clientID + "||service::api.fl.spaces.skype.com::MBI_SSL|"
	graphKey := "msal.2|home|env|accesstoken|" + clientID + "||https://graph.microsoft.com/Files.ReadWrite|"
	idKey := "msal.2|home|env|idtoken|" + clientID + "|||"
	storage := map[string]string{
		"msal.token.keys." + clientID: `{"refreshToken":["` + refreshKey + `"],"idToken":["` + idKey + `"],"accessToken":["` + mbiKey + `","` + graphKey + `"]}`,
		extractedMSALEncryptionCookieKey: mustJSON(t, map[string]string{
			"id":  keyID,
			"key": base64.RawURLEncoding.EncodeToString(baseKey),
		}),
		refreshKey: sealMSALEntry(t, baseKey, keyID, clientID, `{"secret":"refresh-token","expiresOn":"1700000000"}`),
		mbiKey:     sealMSALEntry(t, baseKey, keyID, clientID, `{"secret":"mbi-token","expiresOn":"1700000100","target":"service::api.fl.spaces.skype.com::MBI_SSL"}`),
		graphKey:   sealMSALEntry(t, baseKey, keyID, clientID, `{"secret":"graph-token","expiresOn":"1700000200","target":"https://graph.microsoft.com/Files.ReadWrite"}`),
		idKey:      sealMSALEntry(t, baseKey, keyID, clientID, `{"secret":"id-token"}`),
	}

	state, err := ExtractTokensFromMSALLocalStorage(mustJSON(t, storage), clientID)
	if err != nil {
		t.Fatalf("extract encrypted MSAL storage: %v", err)
	}
	if state.RefreshToken != "refresh-token" {
		t.Fatalf("unexpected refresh token: %q", state.RefreshToken)
	}
	if state.AccessToken != "mbi-token" || state.ExpiresAtUnix != 1700000100 {
		t.Fatalf("unexpected MBI token state: token=%q expiry=%d", state.AccessToken, state.ExpiresAtUnix)
	}
	if state.GraphAccessToken != "graph-token" || state.GraphExpiresAt != 1700000200 {
		t.Fatalf("unexpected Graph token state: token=%q expiry=%d", state.GraphAccessToken, state.GraphExpiresAt)
	}
	if state.IDToken != "id-token" {
		t.Fatalf("unexpected ID token: %q", state.IDToken)
	}
}

func TestExtractTokensFromEncryptedMSALStorageRejectsWrongSessionKey(t *testing.T) {
	t.Parallel()
	baseKey := randomBytes(t, 32)
	const clientID = "client-id"
	refreshKey := "msal.2|home|env|refreshtoken|" + clientID + "|||"
	storage := map[string]string{
		"msal.token.keys." + clientID: `{"refreshToken":["` + refreshKey + `"]}`,
		extractedMSALEncryptionCookieKey: mustJSON(t, map[string]string{
			"id":  "new-session",
			"key": base64.RawURLEncoding.EncodeToString(baseKey),
		}),
		refreshKey: sealMSALEntry(t, baseKey, "old-session", clientID, `{"secret":"refresh-token"}`),
	}

	if _, err := ExtractTokensFromMSALLocalStorage(mustJSON(t, storage), clientID); err == nil {
		t.Fatal("expected extraction to reject an entry from a different MSAL session")
	}
}

func TestExtractTokensFromTeamsAuthCache(t *testing.T) {
	t.Parallel()
	baseKey := randomBytes(t, 32)
	storage := map[string]string{
		"tmp.auth.v1.GLOBAL.ExportedEncryptionKey.ExportedEncryptionKey": mustJSON(t, map[string]any{
			"item": map[string]string{"exportedKey": base64.StdEncoding.EncodeToString(baseKey)},
		}),
		"tmp.auth.v1.GLOBAL.PrimaryUserId.PrimaryUserId": mustJSON(t, map[string]any{
			"item": "live-user",
		}),
		"tmp.auth.v1.live-user.Token.HTTPS://API.FL.SPACES.SKYPE.COM": teamsAuthCacheValue(t, baseKey, "mbi-token", map[string]any{
			"expiration": int64(1_700_000_100_000),
		}),
		"tmp.auth.v1.live-user.Token.HTTPS://GRAPH.MICROSOFT.COM": teamsAuthCacheValue(t, baseKey, "graph-token", map[string]any{
			"expiration": int64(1_700_000_200_000),
		}),
		"tmp.auth.v1.live-user.Discover.SKYPE-TOKEN": teamsAuthCacheValue(t, baseKey, "skype-token", map[string]any{
			"expiration":  int64(1_700_000_300_000),
			"userDetails": map[string]string{"id": "live:tester"},
		}),
		"tmp.auth.v1.other-user.Discover.SKYPE-TOKEN": teamsAuthCacheValue(t, baseKey, "wrong-user-token", map[string]any{
			"expiration":  int64(1_800_000_300_000),
			"userDetails": map[string]string{"id": "live:wrong-user"},
		}),
	}

	state, err := ExtractTokensFromMSALLocalStorage(mustJSON(t, storage), "")
	if err != nil {
		t.Fatalf("extract Teams auth cache: %v", err)
	}
	if state.AccessToken != "mbi-token" || state.ExpiresAtUnix != 1700000100 {
		t.Fatalf("unexpected MBI token state: token=%q expiry=%d", state.AccessToken, state.ExpiresAtUnix)
	}
	if state.GraphAccessToken != "graph-token" || state.GraphExpiresAt != 1700000200 {
		t.Fatalf("unexpected Graph token state: token=%q expiry=%d", state.GraphAccessToken, state.GraphExpiresAt)
	}
	if state.SkypeToken != "skype-token" || state.SkypeTokenExpiresAt != 1700000300 {
		t.Fatalf("unexpected Skype token state: token=%q expiry=%d", state.SkypeToken, state.SkypeTokenExpiresAt)
	}
	if state.TeamsUserID != "live:tester" {
		t.Fatalf("unexpected Teams user ID: %q", state.TeamsUserID)
	}
}

func sealMSALEntry(t *testing.T, baseKey []byte, keyID, context, plaintext string) string {
	t.Helper()
	nonce := randomBytes(t, 16)
	key, err := hkdf.Key(sha256.New, baseKey, nonce, context, 32)
	if err != nil {
		t.Fatalf("derive test key: %v", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("create test cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("create test GCM: %v", err)
	}
	return mustJSON(t, map[string]any{
		"id":            keyID,
		"nonce":         base64.RawURLEncoding.EncodeToString(nonce),
		"data":          base64.RawURLEncoding.EncodeToString(gcm.Seal(nil, make([]byte, gcm.NonceSize()), []byte(plaintext), nil)),
		"lastUpdatedAt": "1700000000000",
	})
}

func teamsAuthCacheValue(t *testing.T, baseKey []byte, plaintext string, extra map[string]any) string {
	t.Helper()
	iv := randomBytes(t, aes.BlockSize)
	block, err := aes.NewCipher(baseKey)
	if err != nil {
		t.Fatalf("create test cipher: %v", err)
	}
	padded := padPKCS7([]byte(plaintext), block.BlockSize())
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)
	item := map[string]any{
		"encryptedToken": base64.StdEncoding.EncodeToString(ciphertext),
		"iv":             base64.StdEncoding.EncodeToString(iv),
	}
	for key, value := range extra {
		item[key] = value
	}
	return mustJSON(t, map[string]any{"item": item})
}

func padPKCS7(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	out := make([]byte, len(plaintext)+padding)
	copy(out, plaintext)
	for i := len(plaintext); i < len(out); i++ {
		out[i] = byte(padding)
	}
	return out
}

func randomBytes(t *testing.T, size int) []byte {
	t.Helper()
	out := make([]byte, size)
	if _, err := rand.Read(out); err != nil {
		t.Fatalf("read random bytes: %v", err)
	}
	return out
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal JSON: %v", err)
	}
	return string(encoded)
}
