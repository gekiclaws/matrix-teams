# Configuration

`mautrix-teams` uses the standard mautrix `bridgev2` config structure plus a small Teams-specific `network` section.

Use [config.example.yaml](../config.example.yaml) for a readable starting point. If you need every framework-level default, generate a full config with `./mautrix-teams -e`.

## Configuration Model

There are two layers:

- Framework config: homeserver, appservice, database, encryption, backfill, logging, provisioning, and common bridge behavior.
- Teams config: the `network` block used by this connector.

That split matters because most knobs are inherited from mautrix, while most Teams behavior is hard-coded in the connector itself.

## Major Sections

### `network`

Teams-specific settings.

- `client_id`
  Required: optional
  Purpose: compatibility fallback for existing logins created before the issuing OAuth client ID was stored in per-login metadata.
  Default behavior: if empty, those older logins use the built-in legacy client ID.
  New device-code logins store and reuse the native Teams client ID, so this setting does not affect them.

### `bridge`

Generic bridge runtime behavior.

Important fields:

- `command_prefix`
  Required: optional
  Used for management-room commands in environments that rely on commands.

- `permissions`
  Required: yes
  Controls which Matrix users can log in and administer the bridge.

- `personal_filtering_spaces`, `private_chat_portal_meta`, `cleanup_on_logout`
  Required: optional
  Affect room organization and cleanup behavior, not Teams protocol behavior.

### `database`

Persistent storage for both bridgev2 state and Teams-specific tables.

- `type`
  Required: yes
  Use `sqlite3-fk-wal` for local development or `postgres` for shared/long-lived deployments.

- `uri`
  Required: yes
  SQLite example: `file:mautrix-teams.db?_txlock=immediate`
  Postgres example: `postgres://user:password@host/mautrix_teams?sslmode=disable`

Sensitive values:

- Postgres URIs usually contain credentials.

### `homeserver`

How the bridge reaches Matrix.

- `address`
  Required: yes
  Base URL the bridge uses to talk to the homeserver.

- `domain`
  Required: yes
  Matrix server name used for MXIDs and appservice registration.

- `software`
  Required: yes
  Usually `standard`. Use `hungry` only when you intentionally target Hungryserv/Beeper-style deployments.

- `websocket`
  Required: optional
  Leave `false` for normal homeservers. Enable only when the homeserver side really supports the mautrix websocket transport.

### `appservice`

How the homeserver reaches the bridge.

- `address`
  Required: yes
  URL the homeserver uses to reach the bridge listener.

- `hostname`, `port`
  Required: yes
  Local bind address for the bridge process.

- `id`
  Required: yes
  Stable appservice ID. Regenerate the registration if you change it.

- `as_token`, `hs_token`
  Required: yes
  Shared secrets for homeserver ↔ appservice communication.

- `bot.username`
  Required: yes
  Localpart for the bridge bot.

Sensitive values:

- `as_token`
- `hs_token`

### `matrix`

Matrix connector behavior.

Useful fields:

- `message_status_events`
- `delivery_receipts`
- `message_error_notices`
- `sync_direct_chat_list`
- `federate_rooms`

These tune Matrix-side UX. They do not change Teams protocol support.

### `provisioning`

Provisioning/API entrypoints for login and management.

- `shared_secret`
  Required: yes if you use provisioning
  Protect this carefully. Anyone with it may be able to drive bridge actions.

- `debug_endpoints`
  Optional
  Useful during maintenance, but higher exposure than a locked-down production deployment.

Sensitive values:

- `shared_secret`

### `backfill`

History import behavior.

This bridge is polling-based, so keep these values conservative until you understand the load profile on both Matrix and Teams.

### `encryption`

End-to-bridge Matrix encryption settings.

This is a mautrix concern, not a Teams protocol concern, but it materially affects operability.

Sensitive values:

- `pickle_key`

### `logging`

Bridge logs.

Default pattern:

- human-readable logs to stdout
- JSON logs to a file such as `./logs/bridge.log`

## Required Vs Optional Summary

Required for any useful deployment:

- `database.type`
- `database.uri`
- `homeserver.address`
- `homeserver.domain`
- `homeserver.software`
- `appservice.address`
- `appservice.hostname`
- `appservice.port`
- `appservice.id`
- `appservice.as_token`
- `appservice.hs_token`
- `appservice.bot.username`
- `bridge.permissions`

Usually optional:

- `network.client_id`
- most `bridge` UX toggles
- most `matrix` toggles
- `backfill`
- `public_media`
- `direct_media`

Required only in specific setups:

- `homeserver.websocket` for websocket-capable homeservers
- `provisioning.shared_secret` if you expose provisioning
- `encryption.*` values for encrypted-room support

## Auth Fields Explained

The bridge stores per-user Teams login state in the database, not in `config.yaml`.

Per-user login metadata includes:

- refresh token
- issuing OAuth client ID
- Skype token
- Graph access token
- token expiry timestamps
- Teams user ID

`config.yaml` only controls the bridge-wide auth environment:

- Matrix appservice auth via `appservice.as_token` and `appservice.hs_token`
- optional provisioning auth via `provisioning.shared_secret`
- optional legacy-login OAuth client-ID fallback via `network.client_id`

## Secret Handling Notes

Treat these as secrets:

- `appservice.as_token`
- `appservice.hs_token`
- `provisioning.shared_secret`
- `double_puppet.secrets`
- `encryption.pickle_key`
- any database password embedded in `database.uri`

Do not commit real values. The example config should stay placeholder-only.

## When To Regenerate Config Or Registration

Regenerate `registration.yaml` after changing:

- `appservice.id`
- `appservice.bot.username`
- appservice transport details that affect registration semantics
- encryption appservice mode settings

Usually no regeneration is needed after changing:

- logging
- database settings
- most bridge behavior flags
- `network.client_id`
