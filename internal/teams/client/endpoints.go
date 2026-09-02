package client

import (
	"errors"
	"net/url"
	"strings"
)

// ConfigureChatServiceURL switches the chat API client from the consumer
// Teams endpoints to the regional service returned by the enterprise Skype
// token exchange.
func (c *Client) ConfigureChatServiceURL(rawURL string) error {
	if c == nil {
		return errors.New("teams client is nil")
	}
	baseURL, err := normalizeChatServiceURL(rawURL)
	if err != nil {
		return err
	}
	c.ConversationsURL = baseURL + "/v1/users/ME/conversations"
	c.MessagesURL = baseURL + "/v1/users/ME/conversations"
	c.SendMessagesURL = baseURL + "/v1/users/ME/conversations"
	c.ConsumptionHorizonsURL = baseURL + "/v1/users/ME/threads"
	return nil
}

func normalizeChatServiceURL(rawURL string) (string, error) {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return "", errors.New("regional chat service URL is empty")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(parsed.Scheme, "https") || parsed.Host == "" {
		return "", errors.New("regional chat service URL must be an absolute HTTPS URL")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errors.New("regional chat service URL must not contain credentials, query parameters, or a fragment")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = strings.TrimRight(parsed.RawPath, "/")
	return strings.TrimRight(parsed.String(), "/"), nil
}
