'use strict'
// Loader for the native addon plus typed errors.
//
// The addon throws plain errors whose message is "<code>: <detail>". This
// wrapper rethrows them as `AnthropicAuthError` with `.code` set, so callers
// can switch on `error.code` without parsing messages.

const { existsSync } = require('node:fs')
const { join } = require('node:path')

const CODES = new Set([
  'auth_required',
  'quota_reserve',
  'invalid_grant',
  'config',
  'invalid_token',
  'store_corrupt',
  'transient',
])

class AnthropicAuthError extends Error {
  constructor(code, message, cause) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'AnthropicAuthError'
    this.code = code
  }
}

function translate(error) {
  if (error instanceof Error && !(error instanceof AnthropicAuthError)) {
    const match = /^([a-z_]+): ([\s\S]*)$/.exec(error.message)
    if (match && CODES.has(match[1])) {
      return new AnthropicAuthError(match[1], match[2], error)
    }
  }
  return error
}

function loadNative() {
  const candidates = [
    process.env.ANTHROPIC_NAPI_PATH,
    join(__dirname, `anthropic-napi.${process.platform}-${process.arch}.node`),
    join(__dirname, 'anthropic-napi.node'),
  ].filter(Boolean)
  for (const candidate of candidates) {
    if (existsSync(candidate)) return require(candidate)
  }
  throw new Error(
    `anthropic-napi: no native binary for ${process.platform}-${process.arch}; ` +
      'build it with `npm run build` (see README)',
  )
}

const native = loadNative()
const inner = new WeakMap()

// Environment the addon resolves endpoints, the default store and OAuth test
// mode from (the same keys as the Rust `Endpoints::from_env`). Passed as a
// snapshot because Bun's `process.env` writes never reach the native
// `getenv`: without this a test preload that sets `process.env` would be
// invisible to Rust, and a forgotten `tokenUrl` would reach production.
const ENV_KEYS = [
  'ANTHROPIC_OAUTH_TEST_MODE',
  'ANTHROPIC_OAUTH_TOKEN_URL',
  'ANTHROPIC_OAUTH_REVOKE_URL',
  'ANTHROPIC_OAUTH_AUTHORIZE_URL',
  'ANTHROPIC_OAUTH_CONSOLE_AUTHORIZE_URL',
  'ANTHROPIC_OAUTH_REDIRECT_URI',
  'ANTHROPIC_OAUTH_USAGE_URL',
  'ANTHROPIC_OAUTH_PROFILE_URL',
  'CLAUDE_CODE_OAUTH_CLIENT_ID',
  'ANTHROPIC_BASE_URL',
  'ANTHROPIC_ACCOUNTS_FILE',
  'ANTHROPIC_ACCOUNTS_DIR',
  'ANTHROPIC_NATIVE_PUBLISH',
  'CLAUDE_CONFIG_DIR',
  'CLAUDE_SECURESTORAGE_CONFIG_DIR',
  'GROK_HOME',
  'HOME',
  'USERPROFILE',
]

function envSnapshot() {
  const out = {}
  for (const key of ENV_KEYS) {
    const value = process.env[key]
    if (typeof value === 'string') out[key] = value
  }
  return out
}

class AnthropicAuth {
  constructor(config) {
    try {
      inner.set(this, new native.AnthropicAuth(config, envSnapshot()))
    } catch (error) {
      throw translate(error)
    }
  }

  get storePath() {
    return inner.get(this).storePath
  }

  get testMode() {
    return inner.get(this).testMode
  }
}

for (const name of Object.getOwnPropertyNames(native.AnthropicAuth.prototype)) {
  if (name === 'constructor') continue
  const descriptor = Object.getOwnPropertyDescriptor(
    native.AnthropicAuth.prototype,
    name,
  )
  if (!descriptor || typeof descriptor.value !== 'function') continue
  AnthropicAuth.prototype[name] = function (...args) {
    let result
    try {
      result = inner.get(this)[name](...args)
    } catch (error) {
      throw translate(error)
    }
    if (result && typeof result.then === 'function') {
      return result.then(undefined, (error) => {
        throw translate(error)
      })
    }
    return result
  }
}

let defaultInstance
function defaultAuth() {
  defaultInstance ??= new AnthropicAuth()
  return defaultInstance
}

module.exports = {
  AnthropicAuth,
  AnthropicAuthError,
  ERROR_CODES: [...CODES],
  listAccounts: (...args) => defaultAuth().listAccounts(...args),
  getAccessToken: (...args) => defaultAuth().getAccessToken(...args),
  markRateLimited: (...args) => defaultAuth().markRateLimited(...args),
  recordQuota: (...args) => defaultAuth().recordQuota(...args),
  recordQuotaHeaders: (...args) => defaultAuth().recordQuotaHeaders(...args),
  markUsed: (...args) => defaultAuth().markUsed(...args),
  setAccountEnabled: (...args) => defaultAuth().setAccountEnabled(...args),
  removeAccount: (...args) => defaultAuth().removeAccount(...args),
  reorderAccounts: (...args) => defaultAuth().reorderAccounts(...args),
  setCurrent: (...args) => defaultAuth().setCurrent(...args),
  keepAliveOnce: (...args) => defaultAuth().keepAliveOnce(...args),
  startLogin: (...args) => defaultAuth().startLogin(...args),
  completeLogin: (...args) => defaultAuth().completeLogin(...args),
  importOAuthAccount: (...args) => defaultAuth().importOAuthAccount(...args),
  handleUnauthorized: (...args) => defaultAuth().handleUnauthorized(...args),
  exchangeCode: (...args) => defaultAuth().exchangeCode(...args),
  addApiKey: (...args) => defaultAuth().addApiKey(...args),
  getApiKey: (...args) => defaultAuth().getApiKey(...args),
  revokeAccount: (...args) => defaultAuth().revokeAccount(...args),
  backfillIdentities: (...args) => defaultAuth().backfillIdentities(...args),
  readNativeClaudeOAuth: (...args) => defaultAuth().readNativeClaudeOAuth(...args),
  importNativeClaudeAccount: (...args) =>
    defaultAuth().importNativeClaudeAccount(...args),
}
