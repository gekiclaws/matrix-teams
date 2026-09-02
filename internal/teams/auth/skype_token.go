package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	skypeTokenErrorSnippetLimit = 2048
	SkypeTokenExpirySkew        = 60 * time.Second
)

type skypeTokenInner struct {
	SkypeToken    string `json:"skypetoken"`
	SkypeTokenAlt string `json:"skypeToken"`
	ExpiresIn     int64  `json:"expiresIn"`
	SkypeID       string `json:"skypeid"`
	SignInName    string `json:"signinname"`
	IsBusiness    bool   `json:"isBusinessTenant"`
}

type skypeTokenRegionGtms struct {
	ChatService    string `json:"chatService"`
	ChatServiceAfd string `json:"chatServiceAfd"`
	AMS            string `json:"ams"`
	AMSV2          string `json:"amsV2"`
}

type skypeTokenResponse struct {
	// Consumer responses use skypeToken. Enterprise responses use tokens and
	// may spell the nested token field as skypeToken.
	SkypeToken skypeTokenInner      `json:"skypeToken"`
	Tokens     skypeTokenInner      `json:"tokens"`
	RegionGtms skypeTokenRegionGtms `json:"regionGtms"`
}

type SkypeTokenResult struct {
	Token          string
	ExpiresAt      int64
	SkypeID        string
	IsBusiness     bool
	ChatServiceURL string
	AMSURL         string
}

func (c *Client) AcquireSkypeToken(ctx context.Context, accessToken string) (*SkypeTokenResult, error) {
	if c.SkypeTokenEndpoint == "" {
		return nil, errors.New("skype token endpoint not configured")
	}
	if accessToken == "" {
		return nil, errors.New("missing access token for skypetoken acquisition")
	}
	if c.Log != nil {
		c.Log.Info().Msg("Acquiring Teams skypetoken")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.SkypeTokenEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		snippet := strings.TrimSpace(readBodySnippet(resp.Body, skypeTokenErrorSnippetLimit))
		if len(snippet) > 400 {
			snippet = snippet[:400] + "...(truncated)"
		}
		if c.Log != nil {
			c.Log.Error().Int("status", resp.StatusCode).Str("body_snippet", snippet).Msg("Failed to acquire skypetoken")
		}
		if snippet == "" {
			return nil, fmt.Errorf("skypetoken endpoint returned non-2xx status: %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("skypetoken endpoint returned non-2xx status: %d body=%s", resp.StatusCode, snippet)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return parseSkypeTokenResponse(body, time.Now().UTC())
}

func parseSkypeTokenResponse(body []byte, now time.Time) (*SkypeTokenResult, error) {
	var payload skypeTokenResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	inner := payload.SkypeToken
	if inner.SkypeToken == "" && inner.SkypeTokenAlt == "" {
		inner = payload.Tokens
	}
	token := inner.SkypeToken
	if token == "" {
		token = inner.SkypeTokenAlt
	}
	if token == "" {
		return nil, errors.New("skypetoken response missing token")
	}

	var expiresAt int64
	if inner.ExpiresIn > 0 {
		expiresAt = now.UTC().Add(time.Duration(inner.ExpiresIn) * time.Second).Unix()
	}
	skypeID := strings.TrimSpace(inner.SkypeID)
	if skypeID == "" {
		skypeID = extractSkypeIDFromJWT(token)
	}
	chatServiceURL := firstNonEmptySkypeEndpoint(payload.RegionGtms.ChatService, payload.RegionGtms.ChatServiceAfd)
	amsURL := firstNonEmptySkypeEndpoint(payload.RegionGtms.AMS, payload.RegionGtms.AMSV2)
	return &SkypeTokenResult{
		Token:          token,
		ExpiresAt:      expiresAt,
		SkypeID:        skypeID,
		IsBusiness:     inner.IsBusiness || payload.Tokens.SkypeToken != "" || payload.Tokens.SkypeTokenAlt != "",
		ChatServiceURL: chatServiceURL,
		AMSURL:         amsURL,
	}, nil
}

func extractSkypeIDFromJWT(token string) string {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		SkypeID string `json:"skypeid"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return strings.TrimSpace(claims.SkypeID)
}

func firstNonEmptySkypeEndpoint(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func (a *AuthState) HasValidSkypeToken(now time.Time) bool {
	if a == nil || a.SkypeToken == "" || a.SkypeTokenExpiresAt == 0 {
		return false
	}
	expiresAt := time.Unix(a.SkypeTokenExpiresAt, 0).UTC()
	return now.UTC().Add(SkypeTokenExpirySkew).Before(expiresAt)
}

func readBodySnippet(r io.Reader, limit int64) string {
	if r == nil || limit <= 0 {
		return ""
	}
	limited := io.LimitReader(r, limit)
	body, _ := io.ReadAll(limited)
	return string(body)
}
