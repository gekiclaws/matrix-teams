package connector

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/database"
	"maunium.net/go/mautrix/bridgev2/networkid"
	"maunium.net/go/mautrix/bridgev2/status"
	"maunium.net/go/mautrix/event"

	internalbridge "go.mau.fi/mautrix-teams/internal/bridge"
	"go.mau.fi/mautrix-teams/internal/teams/auth"
	consumerclient "go.mau.fi/mautrix-teams/internal/teams/client"
	"go.mau.fi/mautrix-teams/pkg/teamsid"
)

type TeamsClient struct {
	Main  *TeamsConnector
	Login *bridgev2.UserLogin
	Meta  *teamsid.UserLoginMetadata

	loggedIn atomic.Bool

	authMu         sync.Mutex
	consumerHTTPMu sync.Mutex
	consumerHTTP   *http.Client

	syncMu     sync.Mutex
	syncCancel context.CancelFunc
	syncDone   chan struct{}

	reactionSeenMu sync.Mutex
	reactionSeen   map[string]struct{}

	receiptPollMu sync.Mutex
	receiptPoll   map[string]time.Time
	unreadMu      sync.Mutex
	unreadSeen    map[string]bool
	unreadSent    map[string]bool
	selfMessageMu sync.Mutex
	selfMessages  map[string]time.Time
}

var (
	_ bridgev2.NetworkAPI                    = (*TeamsClient)(nil)
	_ bridgev2.BackgroundSyncingNetworkAPI   = (*TeamsClient)(nil)
	_ bridgev2.ReactionHandlingNetworkAPI    = (*TeamsClient)(nil)
	_ bridgev2.ReadReceiptHandlingNetworkAPI = (*TeamsClient)(nil)
	_ bridgev2.TypingHandlingNetworkAPI      = (*TeamsClient)(nil)
)

func (c *TeamsClient) Connect(ctx context.Context) {
	if c == nil || c.Login == nil || c.Main == nil {
		return
	}
	if c.Meta == nil {
		if meta, ok := c.Login.Metadata.(*teamsid.UserLoginMetadata); ok {
			c.Meta = meta
		} else {
			c.Meta = &teamsid.UserLoginMetadata{}
			c.Login.Metadata = c.Meta
		}
	}

	c.Login.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnecting})

	if err := c.ensureValidSkypeToken(ctx); err != nil {
		c.loggedIn.Store(false)
		c.Login.Log.Err(err).Msg("Failed to ensure valid Teams tokens")
		c.Login.BridgeState.Send(status.BridgeState{
			StateEvent: status.StateBadCredentials,
			Message:    err.Error(),
			UserAction: status.UserActionRelogin,
		})
		return
	}

	c.loggedIn.Store(true)
	c.Login.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnected})
	c.startSyncLoop()
}

func (c *TeamsClient) Disconnect() {
	c.stopSyncLoop(5 * time.Second)
}

func (c *TeamsClient) IsLoggedIn() bool {
	if c == nil {
		return false
	}
	if c.loggedIn.Load() {
		return true
	}
	if c.Meta == nil {
		if meta, ok := c.Login.Metadata.(*teamsid.UserLoginMetadata); ok {
			c.Meta = meta
		}
	}
	if c.Meta == nil || c.Meta.SkypeToken == "" || c.Meta.SkypeTokenExpiresAt == 0 {
		return false
	}
	expiresAt := time.Unix(c.Meta.SkypeTokenExpiresAt, 0).UTC()
	return time.Now().UTC().Add(auth.SkypeTokenExpirySkew).Before(expiresAt)
}

func (c *TeamsClient) LogoutRemote(ctx context.Context) {
	if c == nil || c.Login == nil {
		return
	}
	c.stopSyncLoop(5 * time.Second)
	if meta, ok := c.Login.Metadata.(*teamsid.UserLoginMetadata); ok && meta != nil {
		*meta = teamsid.UserLoginMetadata{}
	}
	_ = c.Login.Save(ctx)
	c.loggedIn.Store(false)
}

func (c *TeamsClient) IsThisUser(ctx context.Context, userID networkid.UserID) bool {
	_ = ctx
	if c == nil || c.Meta == nil {
		return false
	}
	return strings.TrimSpace(string(userID)) != "" &&
		teamsUserIDToNetworkUserID(c.Meta.TeamsUserID) == userID
}

func (c *TeamsClient) GetChatInfo(ctx context.Context, portal *bridgev2.Portal) (*bridgev2.ChatInfo, error) {
	if c == nil || c.Login == nil || c.Main == nil || c.Main.DB == nil {
		return nil, bridgev2.ErrNotLoggedIn
	}
	threadID := strings.TrimSpace(string(portal.ID))
	if threadID == "" {
		return nil, errors.New("missing thread id")
	}
	row, err := c.Main.DB.ThreadState.Get(ctx, c.Login.ID, threadID)
	if err != nil {
		return nil, err
	}
	if row == nil {
		// Portal can exist before we have a discovery row; return minimal info.
		name := "Chat"
		return &bridgev2.ChatInfo{Name: &name}, nil
	}
	name := row.Name
	var roomType database.RoomType
	if row.IsOneToOne {
		roomType = database.RoomTypeDM
	} else {
		roomType = database.RoomTypeDefault
	}
	return &bridgev2.ChatInfo{
		Name: &name,
		Type: &roomType,
	}, nil
}

func (c *TeamsClient) GetUserInfo(ctx context.Context, ghost *bridgev2.Ghost) (*bridgev2.UserInfo, error) {
	if c == nil || c.Main == nil || c.Main.DB == nil || ghost == nil {
		return nil, bridgev2.ErrNotLoggedIn
	}
	profile, err := c.Main.DB.Profile.GetByTeamsUserID(ctx, string(ghost.ID))
	if err != nil {
		return nil, err
	}
	if profile == nil || strings.TrimSpace(profile.DisplayName) == "" {
		return &bridgev2.UserInfo{Name: ptrString(string(ghost.ID))}, nil
	}
	return &bridgev2.UserInfo{Name: &profile.DisplayName}, nil
}

func (c *TeamsClient) GetCapabilities(ctx context.Context, portal *bridgev2.Portal) *event.RoomFeatures {
	_ = ctx
	_ = portal
	fileFeatures := &event.FileFeatures{
		MimeTypes: map[string]event.CapabilitySupportLevel{
			"*/*": event.CapLevelFullySupported,
		},
		Caption: event.CapLevelFullySupported,
		MaxSize: internalbridge.MaxAttachmentBytesV0,
	}
	return &event.RoomFeatures{
		// Bump when capabilities change so Beeper refreshes cached feature info.
		ID: "fi.mau.teams.capabilities.2026_02_12_3",
		File: event.FileFeatureMap{
			event.MsgFile:  fileFeatures,
			event.MsgImage: fileFeatures,
			event.MsgVideo: fileFeatures,
			event.MsgAudio: fileFeatures,
		},
		Reaction:               event.CapLevelFullySupported,
		TypingNotifications:    true,
		ReadReceipts:           true,
		PerMessageProfileRelay: true,
	}
}

func (c *TeamsClient) ConnectBackground(ctx context.Context, _ *bridgev2.ConnectBackgroundParams) error {
	// For now, background sync just runs one discovery+poll cycle and returns.
	if c == nil {
		return nil
	}
	if err := c.ensureValidSkypeToken(ctx); err != nil {
		return err
	}
	return c.syncOnce(ctx)
}

func (c *TeamsClient) getConsumerHTTP() *http.Client {
	if c == nil {
		return nil
	}
	c.consumerHTTPMu.Lock()
	defer c.consumerHTTPMu.Unlock()
	if c.consumerHTTP != nil {
		return c.consumerHTTP
	}
	authClient := auth.NewClient(nil)
	c.consumerHTTP = authClient.HTTP
	return c.consumerHTTP
}

func (c *TeamsClient) newConsumer() *consumerclient.Client {
	if c == nil {
		return nil
	}
	httpClient := c.getConsumerHTTP()
	if httpClient == nil {
		return nil
	}
	consumer := consumerclient.NewClient(httpClient)
	if c.Login != nil {
		consumer.Log = &c.Login.Log
	}
	if c.Meta != nil {
		consumer.Token = c.Meta.SkypeToken
		if strings.TrimSpace(c.Meta.RegionChatServiceURL) != "" {
			if err := consumer.ConfigureChatServiceURL(c.Meta.RegionChatServiceURL); err != nil {
				if c.Login != nil {
					c.Login.Log.Err(err).Msg("Invalid Teams regional chat service URL")
				}
				return nil
			}
		}
	}
	return consumer
}

func (c *TeamsClient) recordSelfMessage(clientMessageID string) {
	clientMessageID = strings.TrimSpace(clientMessageID)
	if clientMessageID == "" {
		return
	}
	c.selfMessageMu.Lock()
	defer c.selfMessageMu.Unlock()
	now := time.Now().UTC()
	if c.selfMessages == nil {
		c.selfMessages = make(map[string]time.Time)
	}
	c.cleanupSelfMessagesLocked(now)
	c.selfMessages[clientMessageID] = now
}

func (c *TeamsClient) consumeSelfMessage(clientMessageID string) bool {
	clientMessageID = strings.TrimSpace(clientMessageID)
	if clientMessageID == "" {
		return false
	}
	c.selfMessageMu.Lock()
	defer c.selfMessageMu.Unlock()
	if c.selfMessages == nil {
		return false
	}
	now := time.Now().UTC()
	c.cleanupSelfMessagesLocked(now)
	_, exists := c.selfMessages[clientMessageID]
	if exists {
		delete(c.selfMessages, clientMessageID)
	}
	return exists
}

func (c *TeamsClient) cleanupSelfMessagesLocked(now time.Time) {
	if c.selfMessages == nil {
		return
	}
	for id, ts := range c.selfMessages {
		if now.Sub(ts) > selfMessageTTL {
			delete(c.selfMessages, id)
		}
	}
}

func ptrString(v string) *string { return &v }
