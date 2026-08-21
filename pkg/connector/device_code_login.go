// Device-code login adapted from YourSandwich/mautrix-teams.
// Copyright (C) 2026 Sandwich
// SPDX-License-Identifier: AGPL-3.0-or-later

package connector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"

	"go.mau.fi/mautrix-teams/internal/teams/auth"
	"go.mau.fi/mautrix-teams/pkg/teamsid"
)

const (
	FlowIDDeviceCode            = "device_code"
	LoginStepIDDeviceCodePrompt = "fi.mau.teams.login.device_code"
)

var (
	loginFlowDeviceCode = bridgev2.LoginFlow{
		Name:        "Microsoft Teams device code",
		Description: "Log in with a personal Microsoft account using Microsoft's device-code flow.",
		ID:          FlowIDDeviceCode,
	}
	newDeviceCodeClient = auth.NewDeviceCodeClient
)

type DeviceCodeLogin struct {
	Main *TeamsConnector
	User *bridgev2.User

	client     *auth.DeviceCodeClient
	deviceCode string
	interval   time.Duration
	canceled   atomic.Bool
}

var _ bridgev2.LoginProcessDisplayAndWait = (*DeviceCodeLogin)(nil)

func (l *DeviceCodeLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) {
	if l == nil || l.Main == nil || l.User == nil {
		return nil, errors.New("missing login state")
	}
	l.client = newDeviceCodeClient()
	challenge, err := l.client.Start(ctx)
	if err != nil {
		return nil, fmt.Errorf("request device code: %w", err)
	}
	l.deviceCode = challenge.DeviceCode
	l.interval = time.Duration(challenge.Interval) * time.Second

	instructions := fmt.Sprintf(
		"Open %s in a browser and enter the code below. After you approve the login, this step will complete automatically. The code expires in %d minutes.",
		challenge.VerificationURI,
		challenge.ExpiresIn/60,
	)
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeDisplayAndWait,
		StepID:       LoginStepIDDeviceCodePrompt,
		Instructions: instructions,
		DisplayAndWaitParams: &bridgev2.LoginDisplayAndWaitParams{
			Type: bridgev2.LoginDisplayTypeCode,
			Data: challenge.UserCode,
		},
	}, nil
}

func (l *DeviceCodeLogin) Cancel() {
	if l != nil {
		l.canceled.Store(true)
	}
}

func (l *DeviceCodeLogin) Wait(ctx context.Context) (*bridgev2.LoginStep, error) {
	if l == nil || l.client == nil || l.deviceCode == "" {
		return nil, errors.New("device code login not started")
	}
	if l.canceled.Load() {
		return nil, context.Canceled
	}
	state, err := l.client.Poll(ctx, l.deviceCode, l.interval)
	if err != nil {
		return nil, fmt.Errorf("poll device code: %w", err)
	}
	if strings.TrimSpace(state.RefreshToken) == "" {
		return nil, errors.New("device code token response missing refresh token")
	}

	authClient := newAuthClient(nil)
	authClient.ClientID = auth.TeamsPersonalClientID
	authClient.TokenEndpoint = auth.TeamsPersonalTokenURL
	authClient.RedirectURI = ""
	authClient.Scopes = strings.Fields(auth.TeamsPersonalScope)
	personalState, skypeToken, skypeExpiresAt, skypeID, err := acquirePersonalTeamsSkypeToken(ctx, authClient, state.RefreshToken)
	if err != nil {
		return nil, err
	}
	teamsUserID := auth.NormalizeTeamsUserID(skypeID)
	if teamsUserID == "" {
		return nil, errors.New("Teams user ID missing from skypetoken response")
	}

	// Graph is optional for core chat sync. Acquire it best-effort so attachment
	// handling keeps working when the Teams native client is pre-authorized for
	// the delegated Files.ReadWrite scope.
	graphAccessToken := ""
	var graphExpiresAt int64
	refreshToken := strings.TrimSpace(state.RefreshToken)
	if rotated := strings.TrimSpace(personalState.RefreshToken); rotated != "" {
		refreshToken = rotated
	}
	if graphState, graphErr := refreshAccessTokenForGraphScope(ctx, authClient, refreshToken); graphErr == nil {
		graphAccessToken = strings.TrimSpace(graphState.GraphAccessToken)
		graphExpiresAt = graphState.GraphExpiresAt
		if rotated := strings.TrimSpace(graphState.RefreshToken); rotated != "" {
			refreshToken = rotated
		}
	} else {
		l.User.Log.Warn().Err(graphErr).Msg("Device-code login could not prefetch Graph token")
	}

	meta := &teamsid.UserLoginMetadata{
		RefreshToken:         refreshToken,
		AccessTokenExpiresAt: personalState.ExpiresAtUnix,
		OAuthClientID:        auth.TeamsPersonalClientID,
		SkypeToken:           skypeToken,
		SkypeTokenExpiresAt:  skypeExpiresAt,
		GraphAccessToken:     graphAccessToken,
		GraphExpiresAt:       graphExpiresAt,
		TeamsUserID:          teamsUserID,
	}
	ul, err := l.User.NewLogin(ctx, &database.UserLogin{
		ID:         networkid.UserLoginID(teamsUserID),
		RemoteName: teamsUserID,
		Metadata:   meta,
	}, &bridgev2.NewLoginParams{DeleteOnConflict: true})
	if err != nil {
		return nil, err
	}
	startLoginConnect(ul, loginConnectBaseCtx(l.Main))
	return &bridgev2.LoginStep{
		Type:         bridgev2.LoginStepTypeComplete,
		StepID:       "go.mau.teams.complete",
		Instructions: fmt.Sprintf("Successfully logged into Microsoft Teams as %s.", teamsUserID),
		CompleteParams: &bridgev2.LoginCompleteParams{
			UserLoginID: ul.ID,
			UserLogin:   ul,
		},
	}, nil
}

func acquirePersonalTeamsSkypeToken(ctx context.Context, client *auth.Client, refreshToken string) (*auth.AuthState, string, int64, string, error) {
	state, err := client.RefreshAccessToken(ctx, strings.TrimSpace(refreshToken))
	if err != nil {
		return nil, "", 0, "", fmt.Errorf("refresh personal Teams access token: %w", err)
	}
	skypeToken, skypeExpiresAt, skypeID, err := client.AcquireSkypeToken(ctx, state.AccessToken)
	if err != nil {
		return nil, "", 0, "", fmt.Errorf("exchange personal Teams access token for skypetoken: %w", err)
	}
	return state, skypeToken, skypeExpiresAt, skypeID, nil
}
