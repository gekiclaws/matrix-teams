package connector

import (
	"context"
	"fmt"

	"maunium.net/go/mautrix/bridgev2"

	"go.mau.fi/mautrix-teams/pkg/teamsdb"
	"go.mau.fi/mautrix-teams/pkg/teamsid"
)

type TeamsConnector struct {
	Bridge *bridgev2.Bridge
	Config TeamsConfig
	DB     *teamsdb.Database
}

var _ bridgev2.NetworkConnector = (*TeamsConnector)(nil)

func (t *TeamsConnector) GetName() bridgev2.BridgeName {
	return bridgev2.BridgeName{
		DisplayName:      "Microsoft Teams",
		NetworkURL:       "https://www.microsoft.com/microsoft-teams",
		NetworkIcon:      "",
		NetworkID:        "msteams",
		BeeperBridgeType: "msteams",
		DefaultPort:      29340,
	}
}

func (t *TeamsConnector) Init(br *bridgev2.Bridge) {
	t.Bridge = br
	if br != nil && br.DB != nil && br.DB.Database != nil {
		t.DB = teamsdb.New(br.ID, br.DB.Database, br.Log.With().Str("db_section", "teams").Logger())
	}
}

func (t *TeamsConnector) Start(ctx context.Context) error {
	if t.DB == nil {
		return fmt.Errorf("database not initialized")
	}
	if err := t.DB.Upgrade(ctx); err != nil {
		return bridgev2.DBUpgradeError{Err: err, Section: "teams"}
	}
	return nil
}

func (t *TeamsConnector) LoadUserLogin(ctx context.Context, login *bridgev2.UserLogin) error {
	_ = ctx
	// Ensure metadata is the expected concrete type (bridgev2 unmarshals into the type returned by GetDBMetaTypes).
	meta, _ := login.Metadata.(*teamsid.UserLoginMetadata)
	if meta == nil {
		meta = &teamsid.UserLoginMetadata{}
		login.Metadata = meta
	}
	login.Client = &TeamsClient{
		Main:  t,
		Login: login,
		Meta:  meta,
	}
	return nil
}

func (t *TeamsConnector) GetLoginFlows() []bridgev2.LoginFlow {
	return []bridgev2.LoginFlow{loginFlowDeviceCode}
}

func (t *TeamsConnector) CreateLogin(ctx context.Context, user *bridgev2.User, flowID string) (bridgev2.LoginProcess, error) {
	switch flowID {
	case FlowIDDeviceCode:
		return &DeviceCodeLogin{
			Main: t,
			User: user,
		}, nil
	default:
		return nil, bridgev2.ErrInvalidLoginFlowID
	}
}
