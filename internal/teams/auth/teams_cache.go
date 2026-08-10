package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const exportedEncryptionKeyStorageSuffix = ".ExportedEncryptionKey.ExportedEncryptionKey"

// teamsAuthCacheItem is the separate cache format used by Teams' auth layer.
// Unlike MSAL's AES-GCM envelopes, these tokens use AES-256-CBC with the raw
// key and per-token IV stored in adjacent tmp.auth.v1 localStorage entries.
type teamsAuthCacheItem struct {
	Token           string          `json:"token"`
	SkypeToken      string          `json:"skypeToken"`
	EncryptedToken  string          `json:"encryptedToken"`
	IV              string          `json:"iv"`
	Expiration      json.RawMessage `json:"expiration"`
	TokenExpiration json.RawMessage `json:"tokenExpiration"`
	ExpiresOn       json.RawMessage `json:"expiresOn"`
	SkypeID         string          `json:"skypeid"`
	UserDetails     struct {
		ID string `json:"id"`
	} `json:"userDetails"`
}

func extractTeamsAuthTokens(storage map[string]string) (*AuthState, error) {
	baseKey := extractTeamsAuthEncryptionKey(storage)
	primaryUser := extractPrimaryTeamsAuthUser(storage)
	state := &AuthState{}
	var foundCacheEntry bool
	var decryptErr error
	for storageKey, raw := range storage {
		lowerKey := strings.ToLower(storageKey)
		isSkypeToken := strings.HasSuffix(lowerKey, ".discover.skype-token")
		isToken := strings.Contains(lowerKey, ".token.")
		if !isSkypeToken && !isToken {
			continue
		}
		if cacheUser := teamsAuthCacheUser(storageKey); primaryUser != "" && cacheUser != "" && cacheUser != primaryUser {
			continue
		}
		var wrapper struct {
			Item teamsAuthCacheItem `json:"item"`
		}
		if err := json.Unmarshal([]byte(raw), &wrapper); err != nil {
			continue
		}
		item := wrapper.Item
		if item.Token == "" && item.SkypeToken == "" && item.EncryptedToken == "" {
			continue
		}
		foundCacheEntry = true
		decrypted := item.Token
		if isSkypeToken {
			decrypted = item.SkypeToken
		}
		if decrypted == "" && item.EncryptedToken != "" && item.IV != "" && len(baseKey) > 0 {
			var currentDecryptErr error
			decrypted, currentDecryptErr = decryptTeamsAuthToken(baseKey, item.EncryptedToken, item.IV)
			if currentDecryptErr != nil {
				decryptErr = currentDecryptErr
			}
		}
		if decrypted == "" {
			continue
		}
		expiresAt := parseTeamsAuthExpiry(item.TokenExpiration, item.Expiration, item.ExpiresOn)
		switch {
		case isSkypeToken:
			if shouldReplaceCachedToken(state.SkypeToken, state.SkypeTokenExpiresAt, expiresAt) {
				state.SkypeToken = decrypted
				state.SkypeTokenExpiresAt = expiresAt
				state.TeamsUserID = firstNonEmpty(item.UserDetails.ID, item.SkypeID)
			}
		case strings.Contains(lowerKey, "graph.microsoft.com"):
			if shouldReplaceCachedToken(state.GraphAccessToken, state.GraphExpiresAt, expiresAt) {
				state.GraphAccessToken = decrypted
				state.GraphExpiresAt = expiresAt
			}
		case strings.Contains(lowerKey, "spaces.skype.com"):
			if shouldReplaceCachedToken(state.AccessToken, state.ExpiresAtUnix, expiresAt) {
				state.AccessToken = decrypted
				state.ExpiresAtUnix = expiresAt
			}
		}
	}
	if state.SkypeToken == "" && state.AccessToken == "" && state.GraphAccessToken == "" {
		if foundCacheEntry && len(baseKey) == 0 {
			return nil, errors.New("teams auth entries are encrypted but no exported encryption key was found")
		}
		if foundCacheEntry && decryptErr != nil {
			return nil, fmt.Errorf("failed to decrypt Teams auth cache entries: %w", decryptErr)
		}
		return nil, errors.New("teams auth cache entries not found")
	}
	return state, nil
}

func extractTeamsAuthEncryptionKey(storage map[string]string) []byte {
	for storageKey, raw := range storage {
		if !strings.HasSuffix(strings.ToLower(storageKey), strings.ToLower(exportedEncryptionKeyStorageSuffix)) {
			continue
		}
		var wrapper struct {
			Item struct {
				ExportedKey string `json:"exportedKey"`
			} `json:"item"`
		}
		if err := json.Unmarshal([]byte(raw), &wrapper); err != nil {
			continue
		}
		key, err := decodeAuthBase64(wrapper.Item.ExportedKey)
		if err == nil {
			return key
		}
	}
	return nil
}

func extractPrimaryTeamsAuthUser(storage map[string]string) string {
	for storageKey, raw := range storage {
		if !strings.HasSuffix(strings.ToLower(storageKey), ".primaryuserid.primaryuserid") {
			continue
		}
		var wrapper struct {
			Item string `json:"item"`
		}
		if err := json.Unmarshal([]byte(raw), &wrapper); err == nil {
			return strings.TrimSpace(wrapper.Item)
		}
	}
	return ""
}

func teamsAuthCacheUser(storageKey string) string {
	const prefix = "tmp.auth.v1."
	if !strings.HasPrefix(strings.ToLower(storageKey), prefix) {
		return ""
	}
	remainder := storageKey[len(prefix):]
	if separator := strings.IndexByte(remainder, '.'); separator >= 0 {
		return remainder[:separator]
	}
	return ""
}

func shouldReplaceCachedToken(current string, currentExpiry, candidateExpiry int64) bool {
	return current == "" || candidateExpiry > currentExpiry
}

func decryptTeamsAuthToken(baseKey []byte, encryptedToken, encodedIV string) (string, error) {
	ciphertext, err := decodeAuthBase64(encryptedToken)
	if err != nil {
		return "", fmt.Errorf("decode encrypted token: %w", err)
	}
	iv, err := decodeAuthBase64(encodedIV)
	if err != nil {
		return "", fmt.Errorf("decode IV: %w", err)
	}
	block, err := aes.NewCipher(baseKey)
	if err != nil {
		return "", fmt.Errorf("create AES cipher: %w", err)
	}
	if len(iv) != block.BlockSize() {
		return "", errors.New("invalid AES-CBC IV size")
	}
	if len(ciphertext) == 0 || len(ciphertext)%block.BlockSize() != 0 {
		return "", errors.New("invalid AES-CBC ciphertext size")
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)
	plaintext, err = unpadPKCS7(plaintext, block.BlockSize())
	if err != nil {
		return "", err
	}
	if !utf8.Valid(plaintext) || strings.TrimSpace(string(plaintext)) == "" {
		return "", errors.New("decrypted Teams auth token is not valid UTF-8 text")
	}
	return string(plaintext), nil
}

func unpadPKCS7(plaintext []byte, blockSize int) ([]byte, error) {
	if len(plaintext) == 0 || len(plaintext)%blockSize != 0 {
		return nil, errors.New("invalid PKCS#7 plaintext size")
	}
	padding := int(plaintext[len(plaintext)-1])
	if padding == 0 || padding > blockSize || padding > len(plaintext) {
		return nil, errors.New("invalid PKCS#7 padding")
	}
	for _, value := range plaintext[len(plaintext)-padding:] {
		if int(value) != padding {
			return nil, errors.New("invalid PKCS#7 padding")
		}
	}
	return plaintext[:len(plaintext)-padding], nil
}

func parseTeamsAuthExpiry(values ...json.RawMessage) int64 {
	for _, raw := range values {
		trimmed := strings.Trim(strings.TrimSpace(string(raw)), `"`)
		if trimmed == "" || trimmed == "null" {
			continue
		}
		if value, err := strconv.ParseInt(trimmed, 10, 64); err == nil {
			if value > 1_000_000_000_000 {
				value /= 1000
			}
			return value
		}
		if value, ok := parseMSALExpires(trimmed); ok {
			return value
		}
	}
	return 0
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
