package client

import "testing"

func TestConfigureChatServiceURL(t *testing.T) {
	client := NewClient(nil)
	err := client.ConfigureChatServiceURL(" https://amer.ng.msg.teams.microsoft.com/ ")
	if err != nil {
		t.Fatalf("configure regional endpoint: %v", err)
	}
	if client.ConversationsURL != "https://amer.ng.msg.teams.microsoft.com/v1/users/ME/conversations" {
		t.Fatalf("unexpected conversations URL: %q", client.ConversationsURL)
	}
	if client.MessagesURL != client.ConversationsURL || client.SendMessagesURL != client.ConversationsURL {
		t.Fatalf("message endpoints were not routed together: %+v", client)
	}
	if client.ConsumptionHorizonsURL != "https://amer.ng.msg.teams.microsoft.com/v1/users/ME/threads" {
		t.Fatalf("unexpected horizons URL: %q", client.ConsumptionHorizonsURL)
	}
}

func TestConfigureChatServiceURLRejectsUnsafeURLs(t *testing.T) {
	for _, endpoint := range []string{
		"",
		"http://amer.ng.msg.teams.microsoft.com",
		"https://user:pass@amer.ng.msg.teams.microsoft.com",
		"https://amer.ng.msg.teams.microsoft.com?token=secret",
	} {
		client := NewClient(nil)
		if err := client.ConfigureChatServiceURL(endpoint); err == nil {
			t.Fatalf("expected %q to be rejected", endpoint)
		}
	}
}
