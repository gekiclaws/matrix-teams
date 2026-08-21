# Architecture

## Overview

`mautrix-teams` is a mautrix `bridgev2` connector that maps Matrix rooms to Teams chat threads and uses delegated user auth to act as the logged-in Teams user.

The important design choices are:

- New logins use Microsoft's device-code protocol with the native Teams public client.
- Teams ingress is polling-based.
- Attachments depend on delegated Microsoft Graph access.
- The bridge keeps a small Teams-specific state layer on top of bridgev2's normal portal/message/reaction tables.

## Component Map

```mermaid
flowchart TD
    A["Matrix homeserver / appservice"] --> B["mautrix bridgev2 runtime"]
    B --> C["pkg/connector"]
    C --> D["internal/teams/auth"]
    C --> E["internal/teams/client"]
    C --> F["internal/teams/graph"]
    C --> G["pkg/teamsdb"]
    C --> H["internal/bridge"]
```

Component responsibilities:

- `cmd/mautrix-teams`
  Starts `mxmain.BridgeMain` and registers `TeamsConnector`.

- `pkg/connector`
  Owns login flow selection, token refresh hooks, Matrix event handlers, Teams polling, and message conversion.

- `internal/teams/auth`
  Runs device-code auth, refreshes delegated tokens, and exchanges access tokens for Teams `skypetoken` values.

- `internal/teams/client`
  Wraps reverse-engineered Teams consumer HTTP APIs for conversations, messages, reactions, typing indicators, and consumption horizons.

- `internal/teams/graph`
  Handles Graph upload/download work for files.

- `internal/bridge`
  Contains attachment orchestration and Matrix media plumbing reused by the connector.

- `pkg/teamsdb`
  Persists Teams-specific cursors and caches:
  - thread discovery/cursor state
  - observed profile display names
  - last-seen consumption horizons

## Auth Flow

Current auth model: delegated user auth only.

There is no client-credentials flow in the current codebase.

### Delegated Login

```mermaid
sequenceDiagram
    participant U as User
    participant B as User Browser
    participant C as Connector
    participant A as Teams Auth Helpers
    participant T as Teams Token Endpoint
    participant S as Teams Skype Token API

    C->>A: Start device-code login
    A->>T: Request device code
    T-->>A: User code and verification URL
    A-->>C: User code and verification URL
    C-->>U: Display verification URL and code
    U->>B: Sign in and approve code
    C->>A: Poll for completion
    A->>T: Poll for native-client tokens
    T-->>A: Device-flow access and refresh tokens
    A-->>C: Device-flow access and refresh tokens
    C->>A: Refresh for personal Teams MBI scope
    A->>T: Exchange refresh token for MBI access token
    T-->>A: MBI access token and rotated refresh token
    A->>S: Exchange MBI access token for skypetoken
    C->>C: Persist refresh/skype/graph tokens in user_login metadata
```

Notes:

- The connector login flow is `device_code`.
- The issuing OAuth client ID is stored with each login so refresh requests keep using the correct public client.
- The bridge tries to derive both:
  - a Teams chat token path (`skypetoken`)
  - a Graph token for file access

## Teams → Matrix Receive Flow

```mermaid
sequenceDiagram
    participant P as Poll loop
    participant TC as Teams client
    participant DB as teamsdb
    participant BR as bridgev2
    participant MX as Matrix

    P->>TC: List conversations
    P->>DB: Upsert thread state
    P->>BR: Queue chat resync events
    loop Per due thread
        P->>TC: List messages since last sequence ID
        P->>DB: Update profile cache and cursors
        P->>BR: Queue message events
        P->>BR: Queue reaction sync events
        P->>TC: Poll consumption horizons
        P->>BR: Queue read receipt events
    end
    BR->>MX: Emit Matrix events
```

Details:

- Thread discovery runs every 30 seconds.
- Each discovered thread gets its own polling backoff state.
- Successful traffic resets backoff; idle or failing threads slow down.
- Messages are filtered by sequence ID to avoid reprocessing old history.
- Sender display names are cached in `teams_profile`.

## Matrix → Teams Send Flow

```mermaid
sequenceDiagram
    participant MX as Matrix
    participant C as Connector
    participant A as Auth refresh
    participant TC as Teams client
    participant G as Graph

    MX->>C: Message / reaction / typing / receipt event
    C->>A: Ensure valid skypetoken
    alt Text or GIF
        C->>TC: Send Teams message
    else Attachment
        C->>A: Ensure valid Graph token
        C->>G: Upload file + create share link
        C->>TC: Send attachment message
    else Reaction
        C->>TC: Add or remove reaction
    else Typing
        C->>TC: Send typing indicator
    else Read receipt
        C->>TC: Set consumption horizon
    end
```

## Identity And Profile Handling

- Teams users are identified by normalized Teams user IDs and mapped directly into bridgev2 ghost IDs.
- The logged-in Teams user is stored in `UserLoginMetadata.TeamsUserID`.
- Display names are not fetched from a full authoritative profile sync.
- Instead, the bridge updates a profile cache from observed message senders and uses that cache when resolving ghost user info.

Implication:

- Profiles are good enough for active chats.
- Idle contacts may have stale or missing names until they appear in traffic again.

## Stored State

Teams-specific tables:

- `teams_thread_state`
  Stores thread ID, conversation ID, room name, DM/group flag, and last seen sequence ID.

- `teams_profile`
  Stores observed Teams display names.

- `teams_consumption_horizon_state`
  Stores last known inbound read positions for remote participants.

Per-user secret login state is stored in bridgev2's `user_login.metadata` JSON, not in these tables.

## Key Tradeoffs

### Polling Instead Of Push

Pros:

- Simple to reason about.
- No hidden long-lived Teams subscription layer to keep alive.

Cons:

- More latency than a push model.
- More API traffic.
- Backoff behavior matters for both performance and timeliness.

### Reverse-Engineered Teams APIs

Pros:

- Makes the bridge possible at all.

Cons:

- Endpoint formats, token scopes, and payload schemas can break without notice.
- Login extraction depends on Teams web client storage conventions.

### Delegated Graph Access For Files

Pros:

- Enables real file bridging instead of plain links.

Cons:

- File support is only as good as delegated Graph refresh state.
- When Graph token refresh or Drive metadata is missing, inbound attachments degrade to text/link rendering.
