// Type declarations for @coleleavitt/anthropic-napi.
//
// Refresh tokens never cross into JavaScript: no value returned by this API
// carries one. The only method that accepts one (`importOAuthAccount`) moves
// it into the store. API keys are handed out only by `getApiKey`.
//
// Timestamps are epoch milliseconds. Every method rejects/throws an
// `AnthropicAuthError` whose `code` is one of `ErrorCode`.

/** Stable failure classes. */
export type ErrorCode =
  | 'auth_required'
  | 'quota_reserve'
  | 'invalid_grant'
  | 'config'
  | 'invalid_token'
  | 'store_corrupt'
  | 'transient'

export declare const ERROR_CODES: ErrorCode[]

export declare class AnthropicAuthError extends Error {
  readonly name: 'AnthropicAuthError'
  /**
   * - `auth_required`: no account can serve (none, none matching, all disabled); log in.
   * - `quota_reserve`: every otherwise usable account is at/above the reserve or exhausted.
   * - `invalid_grant`: every refreshable account's refresh token is dead/expired; re-login.
   * - `config`: a bad option, or OAuth test mode refused a non-loopback host.
   * - `invalid_token`: a token or key passed in is malformed (wrong shape or kind).
   * - `store_corrupt`: the store (or Claude Code's credential file) is not valid JSON,
   *   is a symlink, or is group/world readable; nothing was written.
   * - `transient`: retry later (rate limit, refresh claim held elsewhere, network, timeout).
   */
  readonly code: ErrorCode
}

/**
 * Store location and endpoint overrides. All optional. Unset endpoints come
 * from the environment (`ANTHROPIC_OAUTH_TOKEN_URL`, `ANTHROPIC_OAUTH_REVOKE_URL`,
 * `ANTHROPIC_OAUTH_AUTHORIZE_URL`, `ANTHROPIC_OAUTH_CONSOLE_AUTHORIZE_URL`,
 * `ANTHROPIC_OAUTH_REDIRECT_URI`, `ANTHROPIC_OAUTH_USAGE_URL`,
 * `CLAUDE_CODE_OAUTH_CLIENT_ID`), else production. With
 * `ANTHROPIC_OAUTH_TEST_MODE=1` any OAuth call to a non-loopback host fails
 * with code `config` before a byte is sent.
 */
export interface AuthConfig {
  /**
   * Store file. Default: `$ANTHROPIC_ACCOUNTS_FILE`, else
   * `$ANTHROPIC_ACCOUNTS_DIR/accounts.json`, else `~/.anthropic-accounts/accounts.json`.
   */
  storePath?: string | null
  /** OAuth token endpoint (tests point this at a mock). */
  tokenUrl?: string | null
  /** Claude.ai authorize URL. */
  authorizeUrl?: string | null
  /** Console authorize URL (`startLogin({ mode: 'console' })`). */
  consoleAuthorizeUrl?: string | null
  /** OAuth redirect URI. */
  redirectUri?: string | null
  /** OAuth client id. */
  clientId?: string | null
  /** Refresh-token revocation endpoint (`ANTHROPIC_OAUTH_REVOKE_URL`). */
  revokeUrl?: string | null
  /** Profile endpoint for identity backfill (`ANTHROPIC_OAUTH_PROFILE_URL`). */
  profileUrl?: string | null
  /**
   * Legacy per-application stores to adopt (flat `~/.grok` / `~/.config/jfc`
   * files). Default: the crate's list (`<store dir>/anthropic-accounts.json`,
   * `$GROK_HOME`, `~/.config/jfc`, `~/.grok`, `~/.config/opencode`) when the
   * store is the default one, none otherwise. `[]` turns adoption off. Rows
   * disabled with `invalid_grant` or without a refresh token are never adopted.
   */
  legacyPaths?: string[] | null
  /**
   * Publish a rotation to Claude Code's credential file when it still holds
   * the spent refresh token (default `'auto'`; `ANTHROPIC_NATIVE_PUBLISH=0`
   * also turns it off). In OAuth test mode only `nativeCredentialsPath` is used.
   */
  nativePublish?: 'auto' | 'off' | null
  /**
   * Claude Code's credential file. Default: `$CLAUDE_SECURESTORAGE_CONFIG_DIR`,
   * else `$CLAUDE_CONFIG_DIR`, else `~/.claude`, joined with `.credentials.json`
   * (never resolved in OAuth test mode).
   */
  nativeCredentialsPath?: string | null
}

export interface QuotaInfo {
  fiveHourPercent?: number
  sevenDayPercent?: number
  checkedAt?: number
}

/** One store row, non-secret fields only. */
export interface AccountInfo {
  id: string
  label?: string
  email?: string
  kind: 'oauth' | 'api_key'
  enabled: boolean
  /** The store's pinned `current` account. */
  current: boolean
  /** Enabled, not cooling down, not exhausted. */
  available: boolean
  /** The access token is live right now. */
  accessLive: boolean
  expiresAt?: number
  refreshExpiresAt?: number
  /** The current refresh token is recorded dead: re-login is required. */
  refreshDead: boolean
  /** Last error, only while it still describes the current token. */
  lastError?: string
  rateLimitedUntil?: number
  lastUsedAt?: number
  lastRefreshedAt?: number
  quota?: QuotaInfo
  accountUuid?: string
  organizationUuid?: string
  scopes: string[]
  /** `api_key` rows: the key's last four characters (never the key). */
  apiKeySuffix?: string
  /**
   * The row is the account Claude Code is logged into (same account and
   * organization): one login, shared and kept in step both ways.
   */
  claudeCodeLinked: boolean
  /**
   * `completeLogin` only: what publishing the new login to Claude Code's
   * credential file did (`written`, `unchanged`, `not_held`, `other_account`,
   * `absent`, `unparseable`, `refused`, `lock_busy`, `failed`).
   */
  claudeCodePublish?: string
  /**
   * `completeLogin` only: a notice for the user. A login of the account Claude
   * Code is logged into replaces Claude Code's login (Anthropic revokes the
   * older one).
   */
  warning?: string
}

export interface GetAccessTokenOptions {
  /** Use only this account (id, email or label). */
  account?: string | null
  /** Consider only these accounts (ids, emails or labels). */
  allowlist?: string[] | null
  /** Skip accounts whose fresh quota reading is at/above this percent (0-100). */
  reservePct?: number | null
}

/** A usable bearer. There is deliberately no refresh token here. */
export interface AccessToken {
  accessToken: string
  accountId: string
  email?: string
  expiresAt: number
  /**
   * `claude_code`: the account is linked to Claude Code's login and its live
   * access token was borrowed (nothing was refreshed).
   */
  source: 'store' | 'refreshed' | 'adopted' | 'claude_code'
}

export interface MarkRateLimitedOptions {
  accountId: string
  /** Cooldown end. Takes precedence over `retryAfterMs`. */
  until?: number | null
  /** Cooldown length from now (from `retry-after`). */
  retryAfterMs?: number | null
}

export interface RecordQuotaOptions {
  /** Either this or `accessToken` identifies the row. */
  accountId?: string | null
  /** The access token the reading was taken with. */
  accessToken?: string | null
  fiveHourPercent?: number | null
  sevenDayPercent?: number | null
  checkedAt?: number | null
}

export interface RecordQuotaHeadersOptions {
  /** The access token the response was obtained with. */
  accessToken: string
  /** Response headers (case-insensitive names), e.g. the unified rate-limit headers. */
  headers: Record<string, string>
}

export interface KeepAliveOnceOptions {
  /** Refresh when the refresh token expires within this many days (default 7). */
  thresholdDays?: number | null
  /** Pause between refreshes in ms (default 2000, jittered). */
  spacingMs?: number | null
}

export interface KeepAliveEntry {
  accountId: string
  /**
   * refreshed: `no_access_token` | `refresh_expiring` | `stale`;
   * failed: `invalid_grant` | `transient`;
   * skipped: `disabled` | `not_oauth` | `no_refresh_token` | `dead_token` |
   * `refresh_expired` | `in_use` | `session_live` | `recently_refreshed` |
   * `not_due` | `deferred` | `claude_code_live` (linked to Claude Code's
   * login, whose access token is live: Claude Code keeps it alive).
   */
  reason: string
  message?: string
}

export interface KeepAliveResult {
  /** `acquired`: this pass did the work; `held`: another pass holds the machine-wide lease. */
  lease: 'acquired' | 'held' | 'no_store'
  heldUntil?: number
  refreshed: KeepAliveEntry[]
  adopted: string[]
  failed: KeepAliveEntry[]
  skipped: KeepAliveEntry[]
}

export interface StartLoginOptions {
  /** `max` (Claude.ai subscription, default) or `console`. */
  mode?: 'max' | 'console' | null
  loginHint?: string | null
  /** Redirect URI for this login only (a loopback listener's). */
  redirectUri?: string | null
  /** Anti-CSRF state for this login (8-512 URL-safe chars). Default: random. */
  state?: string | null
}

/** A login in progress. The PKCE verifier stays in Rust. */
export interface LoginStart {
  /** Open in a browser. */
  url: string
  /** The anti-CSRF state the redirect must echo. */
  state: string
  /** Pass to `completeLogin`. Valid for 30 minutes, in this process. */
  loginId: string
}

export interface CompleteLoginOptions {
  loginId: string
  /** `code#state`, the full redirect URL, a `code=...&state=...` query, or the bare code. */
  callback: string
  /** Label (also the preferred id). */
  label?: string | null
  /** Pin as `current` (default: only when nothing is pinned). */
  setCurrent?: boolean | null
}

export interface ImportOAuthAccountOptions {
  label?: string | null
  accessToken: string
  /** Moves into the store; never returned. */
  refreshToken: string
  expiresAt: number
  refreshExpiresAt?: number | null
  scopes?: string[] | null
  accountUuid?: string | null
  email?: string | null
  organizationUuid?: string | null
}

export interface ImportResult {
  accountId: string
  /**
   * `added`: new row; `already_present`: the store holds this exact token;
   * `kept`: the store already holds this login with its own token (the store wins).
   */
  status: 'added' | 'already_present' | 'kept'
}

/** Result of `importNativeClaudeAccount`. */
export interface NativeImportResult {
  accountId: string
  /**
   * `linked`: Claude Code's `.claude.json` names the account, and the row now
   * shares Claude Code's login (newest copy wins; created when there was no
   * row of that account). Otherwise the one-time copy: `added`,
   * `already_present` or `kept` as for `ImportResult`.
   */
  status: 'added' | 'already_present' | 'kept' | 'linked'
}

export interface HandleUnauthorizedOptions {
  /** The access token the upstream answered 401 to. */
  accessToken: string
}

export interface UnauthorizedResult {
  /** Re-send once with `token`. */
  retry: boolean
  reason: string
  token?: AccessToken
  failureCode?: ErrorCode
}

export interface ExchangeCodeOptions {
  loginId: string
  /** As for `completeLogin`. */
  callback: string
}

/** A code exchanged without storing anything; the refresh token is dropped in Rust. */
export interface ExchangedAccess {
  accessToken: string
  expiresAt: number
  scopes: string[]
  accountUuid?: string
  email?: string
  organizationUuid?: string
}

export interface AddApiKeyOptions {
  label?: string | null
  /** An `sk-ant-api…` key. */
  key: string
}

export interface AddApiKeyResult {
  accountId: string
  status: 'added' | 'already_present'
}

export interface GetApiKeyOptions {
  /** Use only this account (id or label). */
  account?: string | null
  /** Consider only these accounts (ids or labels). */
  allowlist?: string[] | null
}

/** Send `apiKey` as `x-api-key`. Never log it. */
export interface ApiKeyCredential {
  apiKey: string
  accountId: string
  label?: string
}

export interface RevokeAccountOptions {
  accountId: string
  /** Keep the row, disabled with its token recorded dead, instead of removing it. */
  disable?: boolean | null
}

export interface RevokeAccountResult {
  accountId: string
  /** `not_sent`: the token was already recorded dead, no request was needed. */
  outcome: 'revoked' | 'already_inactive' | 'not_sent'
  removed: boolean
}

export interface BackfillEntry {
  accountId: string
  status:
    | 'filled'
    | 'not_oauth'
    | 'already_identified'
    | 'profile_unavailable'
    | 'no_live_access_token'
    | 'changed'
  email?: string
}

export interface NativeClaudeOptions {
  /** Claude Code's credential file (default: the handle's). */
  path?: string | null
  /** Label for an imported row (default `Claude Code`). */
  label?: string | null
}

/** Non-secret facts about Claude Code's credential file. */
export interface NativeClaudeInfo {
  path: string
  expiresAt: number
  refreshExpiresAt?: number
  scopes: string[]
  subscriptionType?: string
  rateLimitTier?: string
  /** The store row holding the same refresh token (its refreshes are published back). */
  storeAccountId?: string
  /** The account Claude Code is logged into (`.claude.json` `oauthAccount`), when known. */
  accountUuid?: string
  organizationUuid?: string
  email?: string
  /** The store row linked to Claude Code's login (same account and organization). */
  linkedAccountId?: string
}

/** A handle on one shared store. Safe to share; every method is independent. */
export declare class AnthropicAuth {
  constructor(config?: AuthConfig | null)
  readonly storePath: string
  /** Whether OAuth calls to non-loopback hosts are refused (`ANTHROPIC_OAUTH_TEST_MODE`). */
  readonly testMode: boolean
  /** Every row, non-secret fields only. */
  listAccounts(): Promise<AccountInfo[]>
  /**
   * A usable access token. Selection, quota reserve, refresh (claimed,
   * through the store), peer adoption and rotation past failing accounts all
   * happen in Rust.
   */
  getAccessToken(options?: GetAccessTokenOptions | null): Promise<AccessToken>
  /** 429 cooldown (also unpins the account). Resolves `false` for an unknown id. */
  markRateLimited(options: MarkRateLimitedOptions): Promise<boolean>
  /** Resolves the account id the reading landed on, or `null`. */
  recordQuota(options: RecordQuotaOptions): Promise<string | null>
  /** Record unified rate-limit headers against the row holding `accessToken`. */
  recordQuotaHeaders(options: RecordQuotaHeadersOptions): Promise<string | null>
  markUsed(accountId: string): Promise<boolean>
  setAccountEnabled(accountId: string, enabled: boolean): Promise<boolean>
  removeAccount(accountId: string): Promise<boolean>
  /** Listed ids first, in order, then the rest. */
  reorderAccounts(orderedIds: string[]): Promise<void>
  setCurrent(accountId: string): Promise<void>
  /** One keep-alive pass over idle accounts; one owner per machine. */
  keepAliveOnce(options?: KeepAliveOnceOptions | null): Promise<KeepAliveResult>
  /** Begin an OAuth PKCE login. */
  startLogin(options?: StartLoginOptions | null): LoginStart
  /** Verify the state, exchange the code, store the account (in place if the login exists). */
  completeLogin(options: CompleteLoginOptions): Promise<AccountInfo>
  /** One-time migration of a host-held credential into the store. */
  importOAuthAccount(options: ImportOAuthAccountOptions): Promise<ImportResult>
  /** One claimed refresh after an upstream 401; retry only on a new bearer. */
  handleUnauthorized(options: HandleUnauthorizedOptions): Promise<UnauthorizedResult>
  /** Exchange a login's code without storing anything (Console API-key mint). */
  exchangeCode(options: ExchangeCodeOptions): Promise<ExchangedAccess>
  /** Store a static API key as an `api_key` row. */
  addApiKey(options: AddApiKeyOptions): Promise<AddApiKeyResult>
  /** A static API key from an `api_key` row (pin first; enabled, not cooling down). */
  getApiKey(options?: GetApiKeyOptions | null): Promise<ApiKeyCredential>
  /** Revoke an OAuth row's refresh token, then remove (or disable) the row. */
  revokeAccount(options: RevokeAccountOptions): Promise<RevokeAccountResult>
  /** Fill uuid/email/organization of unidentified rows from the profile endpoint. */
  backfillIdentities(): Promise<BackfillEntry[]>
  /** Non-secret facts about Claude Code's credential file, or null. */
  readNativeClaudeOAuth(options?: NativeClaudeOptions | null): Promise<NativeClaudeInfo | null>
  /** Import Claude Code's credential into the store (tokens stay in Rust). */
  importNativeClaudeAccount(options?: NativeClaudeOptions | null): Promise<NativeImportResult>
}

// Convenience functions over a lazily created default `AnthropicAuth()` (the
// shared store, production endpoints).
export declare function listAccounts(): Promise<AccountInfo[]>
export declare function getAccessToken(options?: GetAccessTokenOptions | null): Promise<AccessToken>
export declare function markRateLimited(options: MarkRateLimitedOptions): Promise<boolean>
export declare function recordQuota(options: RecordQuotaOptions): Promise<string | null>
export declare function recordQuotaHeaders(options: RecordQuotaHeadersOptions): Promise<string | null>
export declare function markUsed(accountId: string): Promise<boolean>
export declare function setAccountEnabled(accountId: string, enabled: boolean): Promise<boolean>
export declare function removeAccount(accountId: string): Promise<boolean>
export declare function reorderAccounts(orderedIds: string[]): Promise<void>
export declare function setCurrent(accountId: string): Promise<void>
export declare function keepAliveOnce(options?: KeepAliveOnceOptions | null): Promise<KeepAliveResult>
export declare function startLogin(options?: StartLoginOptions | null): LoginStart
export declare function completeLogin(options: CompleteLoginOptions): Promise<AccountInfo>
export declare function importOAuthAccount(options: ImportOAuthAccountOptions): Promise<ImportResult>
export declare function handleUnauthorized(options: HandleUnauthorizedOptions): Promise<UnauthorizedResult>
export declare function exchangeCode(options: ExchangeCodeOptions): Promise<ExchangedAccess>
export declare function addApiKey(options: AddApiKeyOptions): Promise<AddApiKeyResult>
export declare function getApiKey(options?: GetApiKeyOptions | null): Promise<ApiKeyCredential>
export declare function revokeAccount(options: RevokeAccountOptions): Promise<RevokeAccountResult>
export declare function backfillIdentities(): Promise<BackfillEntry[]>
export declare function readNativeClaudeOAuth(options?: NativeClaudeOptions | null): Promise<NativeClaudeInfo | null>
export declare function importNativeClaudeAccount(options?: NativeClaudeOptions | null): Promise<NativeImportResult>
