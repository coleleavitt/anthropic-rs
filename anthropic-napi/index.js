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

class AnthropicAuth {
  constructor(config) {
    try {
      inner.set(this, new native.AnthropicAuth(config))
    } catch (error) {
      throw translate(error)
    }
  }

  get storePath() {
    return inner.get(this).storePath
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
}
