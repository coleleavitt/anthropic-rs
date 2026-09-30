# anthropic

A bare, reusable Anthropic SDK for Rust: complete OAuth PKCE/refresh/revocation, Workload Identity Federation, native credential import, a **shared** multi-account credential store, persistent/trusted/Cowork device contracts, Claude Code 2.1.233 CCH signing, and a minimal Messages API client.

It exists because the same Anthropic auth code kept getting re-implemented per
project, each with its own private credential file. Logging in once should be
enough for every tool on the machine.

## Layers

| Layer | Feature | Links |
|---|---|---|
| Auth domain: secret newtypes, `Credential`, `OAuthTokens`, PKCE, endpoints/scopes | *(always)* | no HTTP client, no filesystem |
| Shared account store at `~/.anthropic-accounts/` | `store` | filesystem |
| `OAuthClient` + `MessagesClient` + `SseDecoder` | `client` | `reqwest` |
| Automatic loopback callback | `interactive-oauth` | Tokio listener |
| Organization/workspace/service-account WIF exchange/cache | `federation` | reqwest + Tokio |
| Native/keyring/file secret import | `store` / `secure-store` | filesystem / OS vault |
| Persistent/trusted/attestation/P-256 device contracts | `device` / `cowork` | RustCrypto |

Auth-only consumers pay for none of the HTTP stack:

```toml
anthropic = { version = "0.1", default-features = false }
```

## The shared credential store

Canonical path: `~/.anthropic-accounts/accounts.json` — deliberately **not**
under any single application's config directory.

Resolution order:

1. an explicit path passed by the caller,
2. `$ANTHROPIC_ACCOUNTS_FILE` (full path),
3. `$ANTHROPIC_ACCOUNTS_DIR/accounts.json`,
4. `$HOME/.anthropic-accounts/accounts.json`.

`AccountStore::load_or_migrate()` falls back to known legacy per-application
locations (`~/.config/jfc/`, `$GROK_HOME/`, `~/.grok/`, `~/.config/opencode/`)
when the canonical file does not exist, and reports the provenance as
`LoadSource::Legacy(path)` so the caller can persist it forward instead of
silently losing an existing login.

Store safety properties, each covered by a test:

- **Atomic writes** — write to a temp sibling, `fsync`, `rename`. A crash
  mid-write leaves the previous store intact rather than a truncated file.
- **Refuses accidental wipes** — ordinary empty saves return `WouldDeleteAllAccounts`; explicit final-account removal uses `save_allow_empty` / `mutate_allow_empty`.
- **Locked mutations and refresh CAS** — an OS advisory lock serializes Rust processes while a short owner/expiry lease coordinates with TypeScript consumers of the same JSON; `replace_oauth_after_refresh` never overwrites a newer rotated token.
- **Symlink refusal** — a store path that became a symlink is a tampering
  signal; reads and writes both refuse to follow it.
- **Orphan sweep** — stale `accounts.json.tmp-*` files from a crashed writer are
  removed, but only when older than an hour, so a concurrent in-flight write is
  never disturbed.
- **`0700` dir / `0600` file** on unix.
- **Secrets never land in plaintext logs** — `Debug` is redacted on every token
  newtype, and `Account::disable(reason)` runs the reason through
  `redact_secrets` before storing it.
- **Row updates never rebuild rows** — fields this crate does not model (on
  the document, on a row, inside a `credential`) are kept verbatim through
  every locked update, so another writer's data survives.
- **Only the store's refresh token is spent** — `OAuthClient::refresh_shared`
  reads the store under its lock, claims the row, and never POSTs a token the
  store does not hold (a stale caller token adopts or refreshes the store's
  newer one). The token call is bounded below the 30 s claim; a result that
  outlives its claim is discarded.
- **Dead only on a real `invalid_grant`** — HTTP 400 with `error ==
  "invalid_grant"`, and only for the token the row still holds.
  `Error::RefreshTokenRevoked { origin }` says whether the endpoint answered
  or a local record short-circuited. `last_error` is bound to the token it
  was recorded against (`Account::current_error()`), so a stale flag clears
  itself on the next locked write.
- **Legacy rows disabled with `invalid_grant` are never imported.**
- **One keep-alive per machine** — `keepalive::keep_alive_once(path, now)`
  refreshes only idle accounts whose refresh token nears expiry (default 7
  days) or that have no access token, behind a store-level lease. Nothing else
  rotates idle accounts.

`access::get_access_token` is the coarse entry point for hosts: selection
(pin first, allowlist, quota reserve), refresh, adoption and rotation past a
failing login, returning an access token and non-secret metadata only.

## Account rotation

```rust
use anthropic::{AccountStore, Error};
use chrono::Utc;

# fn demo(store: &mut AccountStore) -> anthropic::Result<()> {
let now = Utc::now();
let account_id = store.pick(now)?.id.clone();

// on a 429:
store.get_mut(&account_id)?.mark_rate_limited(now + chrono::Duration::minutes(5));
store.rotate_from(&account_id, now);
# Ok(())
# }
```

`pick` skips disabled and rate-limited accounts and prefers the pinned
`current`. Rate-limit cooldowns lapse on their own — no bookkeeping pass needed.

## Login flow

```rust
use anthropic::{Endpoints, parse_redirect_code, start_login};

let login = start_login(&Endpoints::prod())?;
println!("open: {}", login.authorize_url);
// user pastes back "code#state"
let code = parse_redirect_code(&pasted, &login.state)?;
// then: OAuthClient::new(endpoints).exchange_code(&code, &login.verifier, &login.state)
# Ok::<(), anthropic::Error>(())
```

`start_login` returns the URL, verifier, and state together so a caller cannot
build the URL with one PKCE pair and exchange with another. `parse_redirect_code`
compares the returned state in constant time and returns `StateMismatch` on a
mismatch rather than proceeding. With `interactive-oauth`, `LoopbackLogin` binds `127.0.0.1` on a dynamic port, advertises `http://localhost:<port>/callback`, bounds methods/path/request bytes/time, and retains manual paste as a fallback.

Refresh responses preserve refresh-token expiry, scopes, account, and organization metadata when omitted; known-expired refresh tokens fail locally. `OAuthClient::revoke` implements the native token-family revocation body without deleting local state implicitly.

## Federation, native storage, and devices

- `FederationEnvironment` implements Anthropic WIF precedence, projected assertion rereads, 16 KiB bounds, and a single-flight 120s/30s cache.
- Native Claude import derives the `Claude Code[-<config hash>]` vault service and username account, then falls back read-only to `~/.claude/.credentials.json`. Explicit import is separate from discovery.
- `DeviceIdentityStore` persists one 32-byte global ID in `device.json`; trusted-device tokens and Cowork PKCS#8 keys use `SecretStore`, never account JSON.
- Remote Control attestation normalizes every native status and fails malformed enforced policy closed. Cowork uses P-256 SPKI registration and exact P1363 create-session binding.
- `sign_request_body` implements the independently verified 2.1.233 CCH seed `0x4d659218e32a3268` with the 2.1.172+ global model/max-token preimage transform, including nested fields.

## Node / Bun binding (`anthropic-napi`)

The workspace member `anthropic-napi` exposes the store to JavaScript hosts
(the anthropic-auth TypeScript plugin) through Node-API, so they stop keeping
their own token custody. The API is coarse and asynchronous
(`anthropic-napi/index.d.ts`): `listAccounts`, `getAccessToken({ account,
allowlist, reservePct })`, `markRateLimited`, `recordQuota`,
`recordQuotaHeaders`, `markUsed`, `setAccountEnabled`, `removeAccount`,
`reorderAccounts`, `setCurrent`, `keepAliveOnce`, `startLogin` /
`completeLogin` (PKCE; the verifier and the code exchange stay in Rust),
`importOAuthAccount` (one-way migration into the store) and
`handleUnauthorized` (one claimed refresh after a 401). **Refresh tokens never
cross into JavaScript.** Errors are `AnthropicAuthError` with `code` one of
`auth_required`, `quota_reserve`, `invalid_grant`, `config`, `transient`.

Build (plain cargo, no `@napi-rs/cli` needed; the loader looks for
`anthropic-napi.<platform>-<arch>.node` next to `index.js`, or
`$ANTHROPIC_NAPI_PATH`):

```sh
cd anthropic-napi
node scripts/build.mjs          # cargo build --release -p anthropic-napi, then
                                # copies target/release/libanthropic_napi.so to
                                # anthropic-napi.linux-x64.node (honours CARGO_TARGET_DIR)
bun test test/                  # smoke test: temp store + mock token/messages servers
```

```js
const { AnthropicAuth } = require('@coleleavitt/anthropic-napi')
const auth = new AnthropicAuth() // or { storePath, tokenUrl } for tests
const { accessToken, accountId } = await auth.getAccessToken({ reservePct: 90 })
```

The binding requires Rust 1.88+ (napi 3); the core crate stays at 1.85.

## Non-goals

No agent loop, no tool runtime, no session persistence, no prompt templating.
Those belong to the consumer.

## Prior art

Consolidated from `xai-grok-anthropic-auth` (grok-build) and `anthropic-auth`,
plus the hardened atomic-write/orphan-sweep behavior from jfc's
`anthropic_oauth.rs`.

## License

MIT OR Apache-2.0
