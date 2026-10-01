# @coleleavitt/anthropic-napi

Node-API binding (Node ≥ 18 and Bun) over the `anthropic` crate's shared
account store, `~/.anthropic-accounts/accounts.json`. Selection, the quota
reserve, refresh (claimed, compare-and-swap, fail-closed), dead-token
bookkeeping, keep-alive, login, revoke and the Claude Code credential publish
all run in Rust.

**Refresh tokens never reach JavaScript.** No return value carries one. The
only calls that accept one (`importOAuthAccount`, and `importNativeClaudeAccount`,
which reads Claude Code's file itself) move it into the store. API keys come
back only from `getApiKey`; `listAccounts` shows their last four characters.

## Build

```sh
cd anthropic-napi
node scripts/build.mjs          # release; --debug for a debug build
bun test test/                  # smoke + gap suites (mock servers, temp dirs)
```

`scripts/build.mjs` runs plain `cargo build -p anthropic-napi` with whatever
toolchain `cargo` resolves (this repo pins `rustc-master`; never `+stable`),
honours `CARGO_TARGET_DIR`, and copies the library next to `index.js` as
`anthropic-napi.<platform>-<arch>.node`, the name the loader looks for.
`ANTHROPIC_NAPI_PATH` overrides the addon path.

### Consumers: `bun install --force` after every rebuild

A consumer that depends on the package through a `file:` path (the TypeScript
plugin does) gets a **copy** of the directory from Bun. After rebuilding the
addon, run `bun install --force` in the consumer (or delete its
`node_modules/@coleleavitt`) or it keeps loading the old `.node`.

## API

`new AnthropicAuth(config?)` validates the configuration; nothing is read
until a method runs. Every option is optional:

| option | default |
|---|---|
| `storePath` | `$ANTHROPIC_ACCOUNTS_FILE`, else `$ANTHROPIC_ACCOUNTS_DIR/accounts.json`, else `~/.anthropic-accounts/accounts.json` |
| `tokenUrl`, `revokeUrl`, `authorizeUrl`, `consoleAuthorizeUrl`, `redirectUri`, `clientId` | `ANTHROPIC_OAUTH_TOKEN_URL`, `…_REVOKE_URL`, `…_AUTHORIZE_URL`, `…_CONSOLE_AUTHORIZE_URL`, `…_REDIRECT_URI`, `CLAUDE_CODE_OAUTH_CLIENT_ID`, else production |
| `profileUrl` | `ANTHROPIC_OAUTH_PROFILE_URL`, else `https://api.anthropic.com/api/oauth/profile` |
| `legacyPaths` | for the default store: the crate's legacy list (`<store dir>/anthropic-accounts.json`, `$GROK_HOME`, `~/.config/jfc`, `~/.grok`, `~/.config/opencode`); none for any other store; `[]` disables |
| `nativePublish` | `'auto'`; `'off'` or `ANTHROPIC_NATIVE_PUBLISH=0` disables |
| `nativeCredentialsPath` | `$CLAUDE_SECURESTORAGE_CONFIG_DIR` / `$CLAUDE_CONFIG_DIR` / `~/.claude`, + `.credentials.json` (never resolved in test mode) |

`index.js` passes the addon a snapshot of the relevant `process.env` keys,
because Bun's `process.env` writes do not reach the native `getenv`.

| method | what it does |
|---|---|
| `listAccounts()` | every row, non-secret fields (adopts configured legacy stores first) |
| `getAccessToken({account, allowlist, reservePct})` | a live bearer; refresh/adoption/rotation in Rust |
| `handleUnauthorized({accessToken})` | one claimed refresh after an upstream 401 |
| `keepAliveOnce({thresholdDays, spacingMs})` | one machine-wide keep-alive pass |
| `markRateLimited`, `recordQuota`, `recordQuotaHeaders`, `markUsed` | routing bookkeeping |
| `setAccountEnabled`, `removeAccount`, `reorderAccounts`, `setCurrent` | row management |
| `startLogin({mode, loginHint, redirectUri, state})` | PKCE login; the verifier stays in Rust. `redirectUri`/`state` bind one login to a loopback listener |
| `completeLogin({loginId, callback, label, setCurrent})` | exchange and store (in place for a known login); an anonymous grant is named from the profile endpoint. A login of the account Claude Code is logged into replaces Claude Code's: it is published to Claude Code's file and `warning` / `claudeCodePublish` say so |
| `exchangeCode({loginId, callback})` | exchange **without storing** (Console API-key mint); returns the access token only |
| `importOAuthAccount({...})` | one-time move of a host-held credential into the store (the store's copy wins) |
| `addApiKey({label, key})` / `getApiKey({account, allowlist})` | `api_key` rows |
| `revokeAccount({accountId, disable})` | revoke the refresh token at the revoke URL under the row's claim, then remove (or disable) the row; a failed request changes nothing |
| `backfillIdentities()` | fill uuid/email/organization of unidentified rows with their live access token; never refreshes |
| `readNativeClaudeOAuth({path})` | non-secret facts about Claude Code's credential file (+ the store row holding its token, Claude Code's account, and the linked row) |
| `importNativeClaudeAccount({path, label})` | **link** the store to Claude Code's login (status `linked`): the row of Claude Code's account adopts its newer login or publishes its own newer one, or a new row is created; without an identity, the one-time copy. Tokens stay in Rust |

Errors are `AnthropicAuthError` with `.code` one of `auth_required`,
`quota_reserve`, `invalid_grant`, `config` (bad option, or test mode refused a
host), `invalid_token` (a token or key passed in is malformed),
`store_corrupt` (the store or Claude Code's file is not valid JSON, is a
symlink or is group/world readable; nothing was written) or `transient`.
Messages are secret-redacted. `index.d.ts` documents every field.

### One login per account (Claude Code link)

Logging into an Anthropic account revokes that account's older login: Claude
Code and the store cannot each hold an independent login of the same
account. A row whose account uuid and organization uuid equal Claude Code's
`.claude.json` `oauthAccount` is **linked** (`listAccounts` → `claudeCodeLinked`),
and the two share one login, kept in step both ways (newest copy wins):

- `getAccessToken` hands out Claude Code's live access token (`source:
  'claude_code'`) and refreshes nothing; when it has expired, the binding
  refreshes once under Claude Code's own refresh lock and publishes the
  rotation back.
- A newer Claude Code login (the operator ran `claude /login`) is adopted into
  the row: id, label and quota kept, the stale error and dead verdict cleared.
  An `invalid_grant` on a linked row heals this way instead of marking it dead.
- A newer store login (`completeLogin`) or rotation is published to Claude
  Code's `.credentials.json` by account, even over its older (now revoked)
  token; never to a different account, never over a newer Claude Code login.
- `keepAliveOnce` skips linked rows while Claude Code's token is live
  (`claude_code_live`).

Edge cases: when Claude Code's credentials cannot be read for a linked row
(its `.storage-write.lock` stays held past ~7 s, the macOS Keychain is
locked, `security` fails), `getAccessToken` fails with code `transient` and a
`retry in N ms` hint, and the row is neither refreshed nor marked dead; the
next call adopts. A `claude /login` that lands while the store's refresh is in
flight is adopted right after the commit (its token is returned, never the
revoked rotation), and Claude Code's new login is never overwritten. On macOS
Claude Code keeps its credentials in the login Keychain (service
`Claude Code-credentials`, account `$USER`); the crate reaches it through
`/usr/bin/security` (`ANTHROPIC_CLAUDE_CREDENTIALS_BACKEND=file|keychain`
overrides the choice, `ANTHROPIC_SECURITY_BIN` names the binary) with the same
rules. The binding API is unchanged.

Every write to Claude Code's file keeps the old safety: never created, never
through a symlink, never over a file it cannot parse, every other field kept,
0600 through a temp file and rename, under Claude Code's credential-write lock
(`<config dir>/.storage-write.lock`, `proper-lockfile` compatible). The link
follows `nativePublish`: `'off'` or `ANTHROPIC_NATIVE_PUBLISH=0` turns it off.
The same policy (`NativePublish`) is the crate default, so ckl and any other
Rust consumer behave the same way.

## OAuth test mode

With `ANTHROPIC_OAUTH_TEST_MODE=1` (read from the `process.env` snapshot) every
OAuth or profile call to a non-loopback host fails with `config` before a byte
is sent, and Claude Code's real credential file is never resolved: only an
explicit `nativeCredentialsPath` / `path` is read or written. `bun test`
loads `test/preload.ts` (via `bunfig.toml`), which turns test mode on, parks
every OAuth URL (token, revoke, authorize, redirect, usage, profile) on a
dead loopback port and points `HOME` and the store at a temp directory. The
suites use local `Bun.serve` mocks and temp dirs only.

## Publishing to npm

The package is `private` and consumed through a `file:` path today. Publishing
needs what napi-rs projects do:

- one prebuilt addon per target (`linux-x64-gnu`, `linux-arm64-gnu`,
  `darwin-x64`, `darwin-arm64`, `win32-x64-msvc`, …), each in its own package
  (`@coleleavitt/anthropic-napi-linux-x64-gnu`, …) with `os`/`cpu` (and `libc`)
  fields, built in CI on the matching runner or by cross-compiling;
- those packages listed as `optionalDependencies` of the main package at the
  same version, and `index.js` resolving `require('@coleleavitt/anthropic-napi-<triple>')`
  before the local `anthropic-napi.<platform>-<arch>.node` fallback;
- `"private": true` dropped, a real version, and the consumers switched from
  the `file:` path to that version.
