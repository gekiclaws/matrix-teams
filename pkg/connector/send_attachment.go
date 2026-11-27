package connector

import (
	"context"
	"errors"
	"strings"

	"maunium.net/go/mautrix/bridgev2"

	internalbridge "go.mau.fi/mautrix-teams/internal/bridge"
	consumerclient "go.mau.fi/mautrix-teams/internal/teams/client"
	"go.mau.fi/mautrix-teams/internal/teams/graph"
)

func (c *TeamsClient) SendAttachmentMessage(ctx context.Context, threadID string, filename string, content []byte, caption string) error {
	_, err := c.sendAttachmentMessageWithClientMessageID(ctx, threadID, filename, content, caption, "")
	return err
}

func (c *TeamsClient) sendAttachmentMessageWithClientMessageID(ctx context.Context, threadID string, filename string, content []byte, caption string, clientMessageID string) (string, error) {
	if !c.IsLoggedIn() {
		return "", bridgev2.ErrNotLoggedIn
	}
	if err := c.ensureValidSkypeToken(ctx); err != nil {
		return "", err
	}
	if err := c.ensureValidGraphToken(ctx); err != nil {
		return "", err
	}
	threadID = strings.TrimSpace(threadID)
	if threadID == "" {
		return "", errors.New("missing thread id")
	}
	filename = strings.TrimSpace(filename)
	if filename == "" {
		return "", errors.New("missing filename")
	}
	if len(content) == 0 {
		return "", errors.New("missing content")
	}
	if len(content) > internalbridge.MaxAttachmentBytesV0 {
		return "", errors.New("attachment exceeds max size")
	}

	consumer := c.newConsumer()
	if consumer == nil {
		return "", errors.New("missing consumer client")
	}

	graphToken, err := c.Meta.GetGraphAccessToken()
	if err != nil {
		return "", err
	}
	httpClient := c.getConsumerHTTP()
	if httpClient == nil {
		return "", errors.New("missing http client")
	}
	gc := graph.NewClient(httpClient)
	gc.AccessToken = graphToken
	if c.Login != nil {
		gc.Log = &c.Login.Log
	}

	gen := consumerclient.GenerateClientMessageID
	if strings.TrimSpace(clientMessageID) != "" {
		id := strings.TrimSpace(clientMessageID)
		gen = func() string { return id }
	}
	orch := &internalbridge.AttachmentOrchestrator{
		Graph:             gc,
		Teams:             consumer,
		Log:               &c.Login.Log,
		FromUserID:        strings.TrimSpace(c.Meta.TeamsUserID),
		MaxBytes:          internalbridge.MaxAttachmentBytesV0,
		GenerateMessageID: gen,
	}

	sentID, err := orch.SendAttachmentMessage(ctx, threadID, filename, content, caption)
	if err != nil {
		return "", err
	}
	c.recordSelfMessage(sentID)
	return sentID, nil
}
