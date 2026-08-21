# Operations

## Logs

By default, the generated mautrix config writes:

- human-readable logs to stdout
- structured JSON logs to `./logs/bridge.log`

For local debugging, stdout is usually enough. For recurring failures, the JSON log file is easier to grep and correlate.

Useful log themes:

- device-code authorization progress
- token refresh failures
- Teams polling failures
- Graph upload/download failures
- bridge state transitions such as `connected` and `bad_credentials`

## Runtime Behavior To Expect

- Thread discovery runs roughly every 30 seconds.
- Per-thread polling starts fast and backs off when idle or failing.
- A login can appear healthy for text traffic while attachment handling is degraded because Graph token refresh is separate.
- Some failures are best-effort by design: for example, inbound attachments may fall back to textual rendering instead of hard-failing the whole message.

## Common Failure Modes

### First-Run Setup Issues

#### Login Never Completes

Symptoms:

- the login flow sits waiting and never reaches a connected state
- the bridge appears to be waiting for device-code approval

Likely causes:

- the device code expired or was declined
- the Microsoft account used in the browser is not the intended consumer Teams account

What to check:

- whether the device-code URL was opened and approved before it expired
- whether Microsoft displayed the final successful device-sign-in page
- bridge logs for device polling, MBI refresh, or Skype-token exchange errors

#### `bad_credentials` Immediately After Login

Symptoms:

- login completes, but the user state quickly flips to `bad_credentials`

Likely causes:

- the device-flow refresh token was not persisted or was revoked
- Microsoft changed the Skype token exchange behavior

Recovery:

1. Re-run the device-code login and inspect the token refresh and Skype-token exchange logs.
2. If the token exchange itself is failing, treat it as an upstream integration break rather than a config issue.

#### Matrix Side Never Connects

Symptoms:

- the process starts, but the appservice never connects cleanly to Matrix

Likely causes:

- `homeserver.address` or `homeserver.domain` does not match the homeserver
- appservice registration was not installed or tokens do not match
- websocket mode is enabled against a standard homeserver deployment

Recovery:

1. Double-check `homeserver.address`, `homeserver.domain`, `appservice.as_token`, and `appservice.hs_token`.
2. Confirm the generated `registration.yaml` is actually installed on the homeserver side.
3. Leave `homeserver.websocket` disabled unless the homeserver explicitly supports the mautrix websocket transport.

### Auth Or Token Failures

Symptoms:

- Login state flips to `bad_credentials`
- Repeated 401/403 responses from Teams APIs
- Logs mention missing refresh token, Skype token acquisition failure, or Graph token refresh failure

Likely causes:

- Refresh token expired or became invalid
- Microsoft revoked the device-code grant or changed token behavior

Recovery:

1. Re-run the user login flow.
2. Inspect logs for device polling, MBI refresh, and Skype-token exchange errors.
3. If only attachments fail, verify whether the problem is Graph-specific rather than full login breakage.
4. Confirm the account works on `teams.live.com`, not only in an enterprise Teams tenant flow.

### Teams API Breakage

Symptoms:

- Polling starts failing after the bridge previously worked
- Message send requests begin returning persistent 4xx/5xx errors
- Payload parsing or missing-field behavior changes suddenly

Likely causes:

- Microsoft changed a reverse-engineered Teams endpoint
- Message/conversation payload shape changed
- Token exchange behavior changed upstream

Recovery:

1. Capture failing endpoints and status codes from logs.
2. Confirm whether the break is limited to one feature class:
   - login
   - thread discovery
   - send
   - reactions
   - attachments
3. Reproduce with a single known chat to reduce noise.
4. Patch the relevant client/parser code rather than trying to tune config around it.

Operational reality:

- This is the main long-term maintenance cost of the project.

### Rate Limiting

Symptoms:

- Slow delivery
- Repeated retries with backoff
- Eventual success after delays

Current behavior:

- The Teams request executor retries retryable failures.
- Polling backoff respects `429` retry-after when available.
- Idle threads also back off to reduce unnecessary traffic.

Recovery:

1. Avoid aggressive backfill or high-fanout testing while debugging live traffic.
2. Let the bridge settle; do not restart repeatedly unless it is stuck.
3. If needed, reduce operational load by limiting simultaneous active test chats.

### Message Sync Issues

Symptoms:

- Teams messages appear late
- A chat exists but stops updating
- Reactions seem out of sync

Likely causes:

- Polling backoff increased after repeated failures
- Thread discovery no longer returns a conversation mapping
- Sequence cursor or message ID assumptions no longer match Teams responses

Recovery:

1. Check whether thread discovery is still running successfully.
2. Look for repeated errors in `ListConversations` or `ListMessages`.
3. Verify whether the affected chat is a DM or group chat; receipts are more conservative than plain message sync.
4. Re-login if token freshness is suspect.

### Attachment Sync Issues

Symptoms:

- Text bridges, files do not
- Inbound attachments arrive only as links or caption lines
- Outbound file sends fail with Graph-related errors

Likely causes:

- Missing or expired Graph token
- Missing Teams `DriveItemID` on inbound payload
- File exceeds the current 100 MiB in-memory cap
- Login is otherwise healthy, but Graph refresh failed separately from the main Teams token path

Recovery:

1. Re-login to refresh delegated Graph consent and tokens.
2. Confirm whether the failure is inbound, outbound, or both.
3. For large-file failures, reduce file size or raise the cap in code after reviewing memory impact.

## Recovery Playbook

Use this order:

1. Inspect logs for the first real error, not the later cascade.
2. Separate Matrix-side failures from Teams-side failures.
3. Determine whether text messaging still works.
4. If text fails, focus on Skype token / Teams API health.
5. If text works but attachments fail, focus on Graph token health.
6. Re-login before making invasive DB changes.

## Fragility Expectations

You should assume occasional upstream breakage.

Plan for:

- periodic login-flow fixes
- endpoint header/payload adjustments
- attachment-path regressions when Graph or Teams changes behavior

You should not assume:

- enterprise Teams compatibility
- stable undocumented APIs
- zero-maintenance operation over long periods
