// Device-code authentication adapted from YourSandwich/mautrix-teams.
// Copyright (C) 2026 Sandwich
// SPDX-License-Identifier: AGPL-3.0-or-later

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// TeamsPersonalClientID is Microsoft's native public client registration
	// for personal Teams. Unlike the Teams web SPA registration, refresh tokens
	// issued through its device-code flow don't have the SPA's fixed 24-hour
	// lifetime.
	TeamsPersonalClientID = "8ec6bc83-69c8-4392-8f08-b3c986009232"
	TeamsPersonalTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"
	TeamsPersonalResource = "https://api.spaces.skype.com"
	TeamsPersonalScope    = "service::api.fl.spaces.skype.com::MBI_SSL openid profile offline_access"
	TeamsPersonalTokenURL = "https://login.microsoftonline.com/" + TeamsPersonalTenantID + "/oauth2/v2.0/token"

	// The personal Teams client uses the legacy v1 device-code protocol on the
	// common endpoint, then v2 refresh grants against the MSA tenant.
	defaultDeviceCodeTenant = "common"
)

var ErrDeviceCodeDeclined = errors.New("device code login declined by user")

type DeviceCodeResponse struct {
	UserCode        string        `json:"user_code"`
	DeviceCode      string        `json:"device_code"`
	VerificationURL string        `json:"verification_url"`
	VerificationURI string        `json:"verification_uri"`
	ExpiresIn       flexibleInt64 `json:"expires_in"`
	Interval        flexibleInt64 `json:"interval"`
	Message         string        `json:"message"`
}

type deviceCodeTokenResponse struct {
	AccessToken      string        `json:"access_token"`
	RefreshToken     string        `json:"refresh_token"`
	IDToken          string        `json:"id_token"`
	ExpiresIn        flexibleInt64 `json:"expires_in"`
	Error            string        `json:"error"`
	ErrorDescription string        `json:"error_description"`
}

// Microsoft's legacy consumer device-code endpoint encodes numeric fields as
// JSON strings, while the v2 endpoint encodes them as numbers.
type flexibleInt64 int64

func (value *flexibleInt64) UnmarshalJSON(data []byte) error {
	trimmed := strings.Trim(strings.TrimSpace(string(data)), `"`)
	if trimmed == "" || trimmed == "null" {
		*value = 0
		return nil
	}
	parsed, err := strconv.ParseInt(trimmed, 10, 64)
	if err != nil {
		return err
	}
	*value = flexibleInt64(parsed)
	return nil
}

type DeviceCodeClient struct {
	HTTP               *http.Client
	ClientID           string
	Resource           string
	Tenant             string
	DeviceCodeEndpoint string
	TokenEndpoint      string
}

func NewDeviceCodeClient() *DeviceCodeClient {
	return &DeviceCodeClient{
		HTTP:     &http.Client{Timeout: 20 * time.Second},
		ClientID: TeamsPersonalClientID,
		Resource: TeamsPersonalResource,
		Tenant:   defaultDeviceCodeTenant,
	}
}

func (c *DeviceCodeClient) Start(ctx context.Context) (*DeviceCodeResponse, error) {
	if c == nil {
		return nil, errors.New("device code client is nil")
	}
	endpoint := c.DeviceCodeEndpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/devicecode", c.tenant())
	}
	values := url.Values{}
	values.Set("client_id", c.clientID())
	values.Set("resource", c.resource())

	body, status, err := c.postForm(ctx, endpoint, values)
	if err != nil {
		return nil, err
	}
	if status < http.StatusOK || status >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("device code endpoint returned non-2xx status: %d body=%s", status, bodySnippet(body))
	}

	var out DeviceCodeResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode device code response: %w", err)
	}
	if out.VerificationURI == "" {
		out.VerificationURI = out.VerificationURL
	}
	if out.DeviceCode == "" || out.UserCode == "" || out.VerificationURI == "" {
		return nil, errors.New("device code response missing required fields")
	}
	if out.Interval <= 0 {
		out.Interval = 5
	}
	return &out, nil
}

func (c *DeviceCodeClient) Poll(ctx context.Context, deviceCode string, interval time.Duration) (*AuthState, error) {
	if c == nil {
		return nil, errors.New("device code client is nil")
	}
	if strings.TrimSpace(deviceCode) == "" {
		return nil, errors.New("missing device code")
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	endpoint := c.TokenEndpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/token", c.tenant())
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}

		values := url.Values{}
		values.Set("client_id", c.clientID())
		values.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
		values.Set("code", deviceCode)
		body, _, err := c.postForm(ctx, endpoint, values)
		if err != nil {
			return nil, err
		}

		var out deviceCodeTokenResponse
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("decode device code token response: %w", err)
		}
		if out.AccessToken != "" {
			state := &AuthState{
				AccessToken:  out.AccessToken,
				RefreshToken: out.RefreshToken,
				IDToken:      out.IDToken,
			}
			if out.ExpiresIn > 0 {
				state.ExpiresAtUnix = time.Now().UTC().Add(time.Duration(out.ExpiresIn) * time.Second).Unix()
			}
			return state, nil
		}

		switch out.Error {
		case "authorization_pending":
			timer.Reset(interval)
		case "slow_down":
			interval += 5 * time.Second
			timer.Reset(interval)
		case "expired_token", "code_expired":
			return nil, errors.New("device code expired before login completed")
		case "authorization_declined", "access_denied":
			return nil, ErrDeviceCodeDeclined
		default:
			return nil, fmt.Errorf("device code token endpoint: %s: %s", out.Error, out.ErrorDescription)
		}
	}
}

func (c *DeviceCodeClient) postForm(ctx context.Context, endpoint string, values url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

func (c *DeviceCodeClient) tenant() string {
	tenant := strings.TrimSpace(c.Tenant)
	if tenant == "" {
		return defaultDeviceCodeTenant
	}
	return tenant
}

func (c *DeviceCodeClient) clientID() string {
	clientID := strings.TrimSpace(c.ClientID)
	if clientID == "" {
		return TeamsPersonalClientID
	}
	return clientID
}

func (c *DeviceCodeClient) resource() string {
	resource := strings.TrimSpace(c.Resource)
	if resource == "" {
		return TeamsPersonalResource
	}
	return resource
}

func bodySnippet(body []byte) string {
	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 400 {
		return snippet[:400] + "...(truncated)"
	}
	return snippet
}
