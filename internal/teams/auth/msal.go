package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type msalTokenKeys struct {
	RefreshToken []string `json:"refreshToken"`
	IDToken      []string `json:"idToken"`
	AccessToken  []string `json:"accessToken"`
}

type msalTokenEntry struct {
	Secret    string `json:"secret"`
	ExpiresOn string `json:"expiresOn"`
	Target    string `json:"target"`
}

// extractedMSALEncryptionCookieKey is added to the copied storage payload by
// the webview script. MSAL keeps this session key in a cookie, not localStorage.
const extractedMSALEncryptionCookieKey = "__mautrix_teams_msal_cache_encryption"

func ExtractTokensFromMSALLocalStorage(raw string, clientID string) (*AuthState, error) {
	storage, err := parseStorage(raw)
	if err != nil {
		return nil, err
	}
	clientID = resolveMSALClientID(storage, clientID)

	state := &AuthState{}
	var extractionErrors []error
	if msalState, msalErr := extractMSALTokens(storage, clientID); msalErr == nil {
		mergeAuthState(state, msalState)
	} else {
		extractionErrors = append(extractionErrors, msalErr)
	}
	if teamsState, teamsErr := extractTeamsAuthTokens(storage); teamsErr == nil {
		mergeAuthState(state, teamsState)
	} else {
		extractionErrors = append(extractionErrors, teamsErr)
	}

	if state.RefreshToken == "" && state.AccessToken == "" && state.SkypeToken == "" {
		return nil, fmt.Errorf("no usable Teams authentication tokens found: %w", errors.Join(extractionErrors...))
	}
	return state, nil
}

func extractMSALTokens(storage map[string]string, clientID string) (*AuthState, error) {
	cacheKey := extractMSALEncryptionKey(storage)
	keysEntry, err := findMSALKeys(storage, clientID)
	if err != nil {
		return nil, err
	}

	var keys msalTokenKeys
	if err := json.Unmarshal([]byte(keysEntry), &keys); err != nil {
		return nil, err
	}
	if len(keys.RefreshToken) == 0 {
		return nil, errors.New("no refresh token keys in msal token keys")
	}

	refresh, err := readMSALEntry(storage, keys.RefreshToken[0], clientID, cacheKey)
	if err != nil {
		return nil, fmt.Errorf("refresh token entry: %w", err)
	}
	if refresh.Secret == "" {
		return nil, errors.New("refresh token secret missing")
	}

	state := &AuthState{
		RefreshToken: refresh.Secret,
	}
	if refresh.ExpiresOn != "" {
		if parsed, ok := parseMSALExpires(refresh.ExpiresOn); ok {
			state.ExpiresAtUnix = parsed
		}
	}

	if len(keys.AccessToken) > 0 {
		accessToken, expiresAt := selectMBIAccessToken(storage, keys.AccessToken, clientID, cacheKey)
		if accessToken != "" {
			state.AccessToken = accessToken
			if expiresAt != 0 {
				state.ExpiresAtUnix = expiresAt
			}
		}
		graphAccessToken, graphExpiresAt := selectGraphAccessToken(storage, keys.AccessToken, clientID, cacheKey)
		if graphAccessToken != "" {
			state.GraphAccessToken = graphAccessToken
			if graphExpiresAt != 0 {
				state.GraphExpiresAt = graphExpiresAt
			}
		}
	}

	if len(keys.IDToken) > 0 {
		if idToken, err := readMSALEntry(storage, keys.IDToken[0], clientID, cacheKey); err == nil {
			state.IDToken = idToken.Secret
		}
	}

	return state, nil
}

const mbiAccessTokenMarker = "service::api.fl.spaces.skype.com::mbi_ssl"

func selectMBIAccessToken(storage map[string]string, keys []string, clientID string, cacheKey *msalCacheEncryptionKey) (string, int64) {
	var bestToken string
	var bestExpiry int64
	for _, key := range keys {
		entry, err := readMSALEntry(storage, key, clientID, cacheKey)
		if err != nil {
			continue
		}
		if entry.Secret == "" || !matchesMBITarget(entry.Target) {
			continue
		}
		expiry, _ := parseMSALExpires(entry.ExpiresOn)
		if bestToken == "" || expiry > bestExpiry {
			bestToken = entry.Secret
			bestExpiry = expiry
		}
	}
	return bestToken, bestExpiry
}

func matchesMBITarget(target string) bool {
	if target == "" {
		return false
	}
	lower := strings.ToLower(target)
	return strings.Contains(lower, mbiAccessTokenMarker)
}

func selectGraphAccessToken(storage map[string]string, keys []string, clientID string, cacheKey *msalCacheEncryptionKey) (string, int64) {
	var bestToken string
	var bestExpiry int64
	for _, key := range keys {
		entry, err := readMSALEntry(storage, key, clientID, cacheKey)
		if err != nil {
			continue
		}
		if entry.Secret == "" || !matchesGraphTarget(entry.Target) {
			continue
		}
		expiry, _ := parseMSALExpires(entry.ExpiresOn)
		if bestToken == "" || expiry > bestExpiry {
			bestToken = entry.Secret
			bestExpiry = expiry
		}
	}
	return bestToken, bestExpiry
}

func matchesGraphTarget(target string) bool {
	if target == "" {
		return false
	}
	return strings.Contains(strings.ToLower(target), "graph.microsoft.com")
}

func parseStorage(raw string) (map[string]string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("empty localStorage payload")
	}

	var stringMap map[string]string
	if err := json.Unmarshal([]byte(trimmed), &stringMap); err == nil {
		return stringMap, nil
	}

	var anyMap map[string]any
	if err := json.Unmarshal([]byte(trimmed), &anyMap); err != nil {
		return nil, err
	}

	out := make(map[string]string, len(anyMap))
	for key, val := range anyMap {
		switch typed := val.(type) {
		case string:
			out[key] = typed
		default:
			payload, err := json.Marshal(typed)
			if err != nil {
				continue
			}
			out[key] = string(payload)
		}
	}
	return out, nil
}

func findMSALKeys(storage map[string]string, clientID string) (string, error) {
	if storage == nil {
		return "", errors.New("localStorage is empty")
	}
	if clientID != "" {
		key := "msal.token.keys." + clientID
		if val, ok := storage[key]; ok {
			return val, nil
		}
	}

	for key, val := range storage {
		if strings.HasPrefix(key, "msal.token.keys.") {
			return val, nil
		}
	}
	for key, val := range storage {
		if strings.HasPrefix(key, "msal.") && strings.Contains(key, ".token.keys.") {
			return val, nil
		}
	}
	return "", errors.New("msal token keys entry not found")
}

func parseMSALExpires(value string) (int64, bool) {
	if value == "" {
		return 0, false
	}
	if unix, err := strconv.ParseInt(value, 10, 64); err == nil {
		return unix, true
	}
	if parsed, err := time.Parse(time.RFC3339, value); err == nil {
		return parsed.UTC().Unix(), true
	}
	return 0, false
}

type msalCacheEncryptionKey struct {
	ID  string
	Key []byte
}

type msalEncryptedEnvelope struct {
	ID    string `json:"id"`
	Nonce string `json:"nonce"`
	Data  string `json:"data"`
}

func readMSALEntry(storage map[string]string, storageKey, clientID string, cacheKey *msalCacheEncryptionKey) (msalTokenEntry, error) {
	raw, ok := storage[storageKey]
	if !ok {
		return msalTokenEntry{}, errors.New("not found in localStorage")
	}
	plain, err := decryptMSALEntryValue(cacheKey, storageKey, clientID, raw)
	if err != nil {
		return msalTokenEntry{}, err
	}
	var entry msalTokenEntry
	if err := json.Unmarshal([]byte(plain), &entry); err != nil {
		return msalTokenEntry{}, err
	}
	return entry, nil
}

// decryptMSALEntryValue mirrors @azure/msal-browser's encrypted localStorage
// format: HKDF-SHA256 derives an AES-256-GCM key per entry, with a zero IV.
func decryptMSALEntryValue(cacheKey *msalCacheEncryptionKey, storageKey, clientID, rawValue string) (string, error) {
	var envelope msalEncryptedEnvelope
	if err := json.Unmarshal([]byte(rawValue), &envelope); err != nil {
		return rawValue, nil
	}
	if envelope.Data == "" || envelope.Nonce == "" {
		return rawValue, nil
	}
	if cacheKey == nil || len(cacheKey.Key) == 0 {
		return "", errors.New("entry is encrypted but the MSAL encryption cookie was not captured")
	}
	if envelope.ID != "" && cacheKey.ID != "" && envelope.ID != cacheKey.ID {
		return "", errors.New("entry was encrypted with a different MSAL session key")
	}
	nonce, err := decodeAuthBase64(envelope.Nonce)
	if err != nil {
		return "", fmt.Errorf("decode nonce: %w", err)
	}
	ciphertext, err := decodeAuthBase64(envelope.Data)
	if err != nil {
		return "", fmt.Errorf("decode data: %w", err)
	}
	context := ""
	if clientID != "" && strings.Contains(storageKey, clientID) {
		context = clientID
	}
	derivedKey, err := hkdf.Key(sha256.New, cacheKey.Key, nonce, context, 32)
	if err != nil {
		return "", fmt.Errorf("derive key: %w", err)
	}
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create AES-GCM cipher: %w", err)
	}
	plaintext, err := gcm.Open(nil, make([]byte, gcm.NonceSize()), ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt AES-GCM entry: %w", err)
	}
	return string(plaintext), nil
}

func extractMSALEncryptionKey(storage map[string]string) *msalCacheEncryptionKey {
	raw := strings.TrimSpace(storage[extractedMSALEncryptionCookieKey])
	if raw == "" {
		return nil
	}
	var cookie struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if err := json.Unmarshal([]byte(raw), &cookie); err != nil || cookie.Key == "" {
		return nil
	}
	key, err := decodeAuthBase64(cookie.Key)
	if err != nil {
		return nil
	}
	return &msalCacheEncryptionKey{ID: cookie.ID, Key: key}
}

func resolveMSALClientID(storage map[string]string, clientID string) string {
	if strings.TrimSpace(clientID) != "" {
		return clientID
	}
	const marker = ".token.keys."
	for key := range storage {
		if i := strings.Index(key, marker); i != -1 {
			return key[i+len(marker):]
		}
	}
	return ""
}

func decodeAuthBase64(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
	} {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
	}
	return nil, errors.New("invalid base64")
}

func mergeAuthState(destination, source *AuthState) {
	if destination == nil || source == nil {
		return
	}
	if destination.AccessToken == "" {
		destination.AccessToken = source.AccessToken
		destination.ExpiresAtUnix = source.ExpiresAtUnix
	}
	if destination.RefreshToken == "" {
		destination.RefreshToken = source.RefreshToken
	}
	if destination.IDToken == "" {
		destination.IDToken = source.IDToken
	}
	if destination.SkypeToken == "" {
		destination.SkypeToken = source.SkypeToken
		destination.SkypeTokenExpiresAt = source.SkypeTokenExpiresAt
	}
	if destination.GraphAccessToken == "" {
		destination.GraphAccessToken = source.GraphAccessToken
		destination.GraphExpiresAt = source.GraphExpiresAt
	}
	if destination.TeamsUserID == "" {
		destination.TeamsUserID = source.TeamsUserID
	}
}
