package connector

import (
	"testing"

	"go.mau.fi/mautrix-teams/pkg/teamsid"
)

func TestNewConsumerUsesPersistedRegionalChatService(t *testing.T) {
	client := &TeamsClient{Meta: &teamsid.UserLoginMetadata{
		SkypeToken:           "enterprise-token",
		RegionChatServiceURL: "https://emea.ng.msg.teams.microsoft.com",
	}}
	consumer := client.newConsumer()
	if consumer.Token != "enterprise-token" {
		t.Fatalf("unexpected token: %q", consumer.Token)
	}
	if consumer.ConversationsURL != "https://emea.ng.msg.teams.microsoft.com/v1/users/ME/conversations" {
		t.Fatalf("unexpected regional conversations URL: %q", consumer.ConversationsURL)
	}
	if consumer.SendMessagesURL != consumer.ConversationsURL || consumer.MessagesURL != consumer.ConversationsURL {
		t.Fatalf("regional message endpoints are inconsistent: %+v", consumer)
	}
}
