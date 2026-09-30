// Type declarations for @coleleavitt/anthropic-napi.
//
// Refresh tokens never cross into JavaScript: no value returned by this API
// carries one. The only method that accepts one (`importOAuthAccount`) moves
// it into the store.
//
// Timestamps are epoch milliseconds. Every method rejects/throws an
// `AnthropicAuthError` whose `code` is one of `ErrorCode`.

/** Stable failure classes. */
export type ErrorCode =
  | 'auth_required'
  | 'quota_reserve'
  | 'invalid_grant'
  | 'config'
  | 'transient'

export declare const ERROR_CODES: ErrorCode[]

export declare class AnthropicAuthError extends Error {
  readonly name: 'AnthropicAuthError'
  /**
   * - `auth_required`: no account can serve (none, none matching, all disabled); log in.
   * - `quota_reserve`: every otherwise usable account is at/above the reserve or exhausted.
   * - `invalid_grant`: every refreshable account's refresh token is dead/expired; re-login.
   * - `config`: unusable store or option, or OAuth test mode refused a non-loopback host.
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
  source: 'store' | 'refreshed' | 'adopted'
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
   * `not_due` | `deferred`.
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
