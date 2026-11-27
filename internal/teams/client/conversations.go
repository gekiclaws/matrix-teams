package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"go.mau.fi/mautrix-teams/internal/teams/model"
)

const (
	defaultConversationsURL = "https://msgapi.teams.live.com/v1/users/ME/conversations?startTime=0&view=msnp24Equivalent&pageSize=200"
	maxErrorBodyBytes       = 2048
)

var ErrMissingHTTPClient = errors.New("consumer client missing http client")

type ConversationsError struct {
	Status      int
	BodySnippet string
}

func (e ConversationsError) Error() string {
	return "conversations request failed"
}

type Client struct {
	HTTP                   *http.Client
	Executor               *TeamsRequestExecutor
	ConversationsURL       string
	MessagesURL            string
	SendMessagesURL        string
	ConsumptionHorizonsURL string
	Token                  string
	Log                    *zerolog.Logger
}

func NewClient(httpClient *http.Client) *Client {
	executor := &TeamsRequestExecutor{
		HTTP:        httpClient,
		Log:         zerolog.Nop(),
		MaxRetries:  4,
		BaseBackoff: 500 * time.Millisecond,
		MaxBackoff:  10 * time.Second,
	}
	return &Client{
		HTTP:                   httpClient,
		Executor:               executor,
		ConversationsURL:       defaultConversationsURL,
		SendMessagesURL:        defaultSendMessagesURL,
		ConsumptionHorizonsURL: defaultConsumptionHorizonsURL,
	}
}

func (c *Client) ListConversations(ctx context.Context, token string) ([]model.RemoteConversation, error) {
	if c == nil || c.HTTP == nil {
		return nil, ErrMissingHTTPClient
	}
	endpoint := c.ConversationsURL
	if endpoint == "" {
		endpoint = defaultConversationsURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("authentication", "skypetoken="+token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
		return nil, ConversationsError{
			Status:      resp.StatusCode,
			BodySnippet: string(snippet),
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var payload struct {
		Conversations []model.RemoteConversation `json:"conversations"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, err
	}
	return payload.Conversations, nil
}
