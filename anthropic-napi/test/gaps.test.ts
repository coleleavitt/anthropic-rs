// Binding surface added for the TS plugin's remaining gaps: native Claude Code
// publish and import, revoke, API-key rows, legacy adoption, per-login
// redirect/state, the non-persisting code exchange, identity backfill and the
// split error codes. Temp dirs and local mock servers only: nothing here
// reads or writes the real ~/.claude, ~/.anthropic-accounts or any Anthropic
// endpoint (test/preload.ts turns on OAuth test mode first).
import { afterAll, beforeEach, describe, expect, test } from 'bun:test'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const sandbox = mkdtempSync(join(tmpdir(), 'anthropic-napi-gaps-'))
process.env.ANTHROPIC_ACCOUNTS_FILE = join(sandbox, 'default-accounts.json')
process.env.HOME = sandbox

const { AnthropicAuth, AnthropicAuthError, ERROR_CODES } = require('../index.js')

const HOUR = 3_600_000
const DAY = 24 * HOUR
const SHARED_REFRESH = 'sk-ant-ort01-sharedsharedsharedshared00'
const SHARED_ACCESS = 'sk-ant-oat01-sharedsharedsharedshared00'
const API_KEY = 'sk-ant-api03-keykeykeykeykeykeykeykeyWXYZ'

// ---- mock OAuth surface ----------------------------------------------------
const presented: string[] = []
const exchanges: Array<Record<string, string>> = []
const revoked: Array<Record<string, string>> = []
const profileBearers: string[] = []
let rotation = 0
let revokeStatus = 200
const server = Bun.serve({
  port: 0,
  async fetch(req) {
    const url = new URL(req.url)
    if (req.method === 'GET' && url.pathname === '/api/oauth/profile') {
      const bearer = req.headers.get('authorization') ?? ''
      profileBearers.push(bearer)
      if (!bearer.startsWith('Bearer sk-ant-oat01-')) return new Response('{}', { status: 401 })
      return Response.json({
        account: { uuid: 'acct-profile', email: 'profile@example.com' },
        organization: { uuid: 'org-profile' },
      })
    }
    if (req.method !== 'POST') return new Response('not found', { status: 404 })
    const body = (await req.json()) as Record<string, string>
    if (url.pathname === '/v1/oauth/token/revoke') {
      revoked.push(body)
      if (revokeStatus !== 200) return Response.json({ error: 'unavailable' }, { status: revokeStatus })
      return Response.json({})
    }
    if (url.pathname !== '/v1/oauth/token') return new Response('not found', { status: 404 })
    if (body.grant_type === 'refresh_token') {
      presented.push(body.refresh_token)
      rotation += 1
      return Response.json({
        access_token: `sk-ant-oat01-rotated${rotation}rotatedrotatedrot00`,
        refresh_token: `sk-ant-ort01-rotated${rotation}rotatedrotatedrot00`,
        expires_in: 28_800,
        scope: 'user:inference user:profile',
      })
    }
    if (body.grant_type === 'authorization_code') {
      exchanges.push(body)
      return Response.json({
        access_token: 'sk-ant-oat01-exchangedexchangedexchang00',
        refresh_token: 'sk-ant-ort01-exchangedexchangedexchang00',
        expires_in: 28_800,
        scope: 'org:create_api_key user:profile user:inference',
        // An anonymous grant: the identity comes from the profile endpoint.
        ...(body.code === 'anon-code'
          ? {}
          : { account: { uuid: 'acct-code', email_address: 'code@example.com' } }),
      })
    }
    return Response.json({ error: 'unsupported_grant_type' }, { status: 400 })
  },
})
const base = `http://127.0.0.1:${server.port}`
const tokenUrl = `${base}/v1/oauth/token`
const revokeUrl = `${base}/v1/oauth/token/revoke`
const profileUrl = `${base}/api/oauth/profile`

afterAll(() => {
  server.stop(true)
  rmSync(sandbox, { recursive: true, force: true })
})

// ---- helpers ---------------------------------------------------------------
let dir = ''
let storePath = ''
let n = 0

beforeEach(() => {
  n += 1
  dir = join(sandbox, `case-${n}`)
  mkdirSync(dir, { recursive: true })
  storePath = join(dir, 'accounts.json')
  presented.length = 0
  exchanges.length = 0
  revoked.length = 0
  profileBearers.length = 0
  revokeStatus = 200
})

function oauthRow(id: string, opts: { refresh?: string; access?: string; expiresIn?: number; uuid?: string } = {}) {
  const now = Date.now()
  return {
    id,
    credential: {
      type: 'oauth',
      access: opts.access ?? SHARED_ACCESS,
      refresh: opts.refresh ?? SHARED_REFRESH,
      expires_at: now + (opts.expiresIn ?? -HOUR),
      refresh_expires_at: now + 20 * DAY,
      scopes: ['user:inference', 'user:profile'],
      ...(opts.uuid ? { account: { uuid: opts.uuid } } : {}),
    },
    enabled: true,
    created_at: new Date(now - DAY).toISOString(),
  }
}

function seed(accounts: unknown[], extra: Record<string, unknown> = {}) {
  writeFileSync(storePath, JSON.stringify({ version: 1, accounts, ...extra }), { mode: 0o600 })
}

function readStore(): any {
  return JSON.parse(readFileSync(storePath, 'utf8'))
}

/** Claude Code's credential file, the shape it writes (0600). */
function nativeFile(refresh: string, extra: Record<string, unknown> = {}) {
  const configDir = join(dir, 'claude-config')
  mkdirSync(configDir, { recursive: true })
  const path = join(configDir, '.credentials.json')
  writeFileSync(
    path,
    JSON.stringify({
      claudeAiOauth: {
        accessToken: 'sk-ant-oat01-nativenativenativenative00',
        refreshToken: refresh,
        expiresAt: Date.now() - HOUR,
        refreshTokenExpiresAt: Date.now() + 20 * DAY,
        scopes: ['user:inference', 'user:profile'],
        subscriptionType: 'max',
        rateLimitTier: 'default_claude_max_20x',
      },
      mcpOAuth: { server: { keep: true } },
      ...extra,
    }),
    { mode: 0o600 },
  )
  return path
}

function readJson(path: string): any {
  return JSON.parse(readFileSync(path, 'utf8'))
}

async function expectCode(promise: Promise<unknown>, code: string) {
  let caught: any
  try {
    await promise
  } catch (error) {
    caught = error
  }
  expect(caught).toBeInstanceOf(AnthropicAuthError)
  expect(caught.code).toBe(code)
  expect(String(caught.message)).not.toContain('sk-ant-')
  return caught
}

// ---- native Claude Code publish ---------------------------------------------
describe('native Claude Code publish', () => {
  test('a store refresh of the token Claude Code holds is published to its file', async () => {
    seed([oauthRow('shared')])
    const native = nativeFile(SHARED_REFRESH)
    const a = new AnthropicAuth({ storePath, tokenUrl, nativeCredentialsPath: native })
    const token = await a.getAccessToken()
    expect(token.source).toBe('refreshed')
    expect(presented).toEqual([SHARED_REFRESH])
    const doc = readJson(native)
    expect(doc.claudeAiOauth.refreshToken).toMatch(/^sk-ant-ort01-rotated\d+rotated/)
    expect(doc.claudeAiOauth.accessToken).toBe(token.accessToken)
    expect(doc.claudeAiOauth.expiresAt).toBe(token.expiresAt)
    expect(doc.claudeAiOauth.subscriptionType).toBe('max')
    expect(doc.mcpOAuth).toEqual({ server: { keep: true } })
    expect(statSync(native).mode & 0o777).toBe(0o600)
    expect(existsSync(join(dir, 'claude-config', '.storage-write.lock'))).toBe(false)
    // The store and Claude Code agree now.
    expect(readStore().accounts[0].credential.refresh).toBe(doc.claudeAiOauth.refreshToken)
  })

  test('a file holding another token, nativePublish off, or test mode without a path: untouched', async () => {
    for (const setup of ['foreign', 'off', 'default'] as const) {
      seed([oauthRow('shared')])
      const native = nativeFile(setup === 'foreign' ? 'sk-ant-ort01-claudecoderotateditself00' : SHARED_REFRESH)
      const before = readFileSync(native)
      const config =
        setup === 'foreign'
          ? { storePath, tokenUrl, nativeCredentialsPath: native }
          : setup === 'off'
            ? { storePath, tokenUrl, nativeCredentialsPath: native, nativePublish: 'off' }
            : { storePath, tokenUrl }
      // `default`: Claude Code's own path resolves to this file through
      // CLAUDE_CONFIG_DIR, but a test-mode handle never resolves it.
      process.env.CLAUDE_CONFIG_DIR = join(dir, 'claude-config')
      try {
        const a = new AnthropicAuth(config)
        expect((await a.getAccessToken()).source).toBe('refreshed')
      } finally {
        delete process.env.CLAUDE_CONFIG_DIR
      }
      expect(readFileSync(native).equals(before)).toBe(true)
    }
    expect(() => new AnthropicAuth({ storePath, nativePublish: 'sometimes' })).toThrow(AnthropicAuthError)
  })

  test('outside test mode the default follows CLAUDE_CONFIG_DIR; ANTHROPIC_NATIVE_PUBLISH=0 turns it off', async () => {
    // Every URL here is still a loopback mock or the preload's dead port;
    // only the native-file sandbox rule is lifted, and the file is a temp one.
    const saved = process.env.ANTHROPIC_OAUTH_TEST_MODE
    process.env.ANTHROPIC_OAUTH_TEST_MODE = '0'
    process.env.CLAUDE_CONFIG_DIR = join(dir, 'claude-config')
    try {
      for (const off of [false, true]) {
        seed([oauthRow('shared')])
        const native = nativeFile(SHARED_REFRESH)
        if (off) process.env.ANTHROPIC_NATIVE_PUBLISH = '0'
        const a = new AnthropicAuth({ storePath, tokenUrl })
        expect(a.testMode).toBe(false)
        const token = await a.getAccessToken()
        const held = readJson(native).claudeAiOauth.refreshToken
        expect(held === SHARED_REFRESH).toBe(off)
        if (!off) expect(readJson(native).claudeAiOauth.accessToken).toBe(token.accessToken)
      }
    } finally {
      process.env.ANTHROPIC_OAUTH_TEST_MODE = saved
      delete process.env.CLAUDE_CONFIG_DIR
      delete process.env.ANTHROPIC_NATIVE_PUBLISH
    }
  })

  test('import-native moves the tokens in Rust; later refreshes keep Claude Code alive', async () => {
    const native = nativeFile(SHARED_REFRESH)
    const a = new AnthropicAuth({ storePath, tokenUrl, profileUrl, nativeCredentialsPath: native })
    const info = await a.readNativeClaudeOAuth()
    expect(info).toMatchObject({
      path: native,
      subscriptionType: 'max',
      rateLimitTier: 'default_claude_max_20x',
      scopes: ['user:inference', 'user:profile'],
    })
    expect(info.storeAccountId).toBeUndefined()
    expect(JSON.stringify(info)).not.toContain('sk-ant-')

    const imported = await a.importNativeClaudeAccount()
    expect(imported).toEqual({ accountId: 'Claude Code', status: 'added' })
    expect(JSON.stringify(imported)).not.toContain('sk-ant-')
    expect((await a.readNativeClaudeOAuth()).storeAccountId).toBe('Claude Code')
    expect(await a.importNativeClaudeAccount()).toEqual({ accountId: 'Claude Code', status: 'already_present' })

    // The imported access token is expired: the store refreshes it and
    // Claude Code's file follows.
    const token = await a.getAccessToken()
    expect(token.source).toBe('refreshed')
    expect(readJson(native).claudeAiOauth.accessToken).toBe(token.accessToken)
    expect((await a.readNativeClaudeOAuth()).storeAccountId).toBe('Claude Code')
  })

  test('native read/import: absent, sandboxed in test mode, unusable files typed', async () => {
    const a = new AnthropicAuth({ storePath, tokenUrl })
    // Test mode and no explicit path: the real file is never read.
    expect(await a.readNativeClaudeOAuth()).toBeNull()
    await expectCode(a.importNativeClaudeAccount(), 'auth_required')
    const missing = join(dir, 'nope', '.credentials.json')
    expect(await a.readNativeClaudeOAuth({ path: missing })).toBeNull()
    await expectCode(a.importNativeClaudeAccount({ path: missing }), 'auth_required')
    const bad = join(dir, 'bad.json')
    writeFileSync(bad, 'not json', { mode: 0o600 })
    await expectCode(a.readNativeClaudeOAuth({ path: bad }), 'store_corrupt')
    const open = nativeFile(SHARED_REFRESH)
    chmodSync(open, 0o644)
    await expectCode(a.importNativeClaudeAccount({ path: open }), 'store_corrupt')
    expect(existsSync(storePath)).toBe(false)
  })
})

// ---- revoke ----------------------------------------------------------------
describe('revokeAccount', () => {
  test('revokes at the (mock) revoke URL, then removes or disables the row', async () => {
    seed([
      oauthRow('a', { refresh: 'sk-ant-ort01-aaaaaaaaaaaaaaaaaaaaaaaa00' }),
      oauthRow('b', { refresh: 'sk-ant-ort01-bbbbbbbbbbbbbbbbbbbbbbbb00' }),
    ])
    const a = new AnthropicAuth({ storePath, tokenUrl, revokeUrl })
    expect(await a.revokeAccount({ accountId: 'a' })).toEqual({
      accountId: 'a',
      outcome: 'revoked',
      removed: true,
    })
    expect(revoked).toEqual([
      expect.objectContaining({
        token: 'sk-ant-ort01-aaaaaaaaaaaaaaaaaaaaaaaa00',
        token_type_hint: 'refresh_token',
      }),
    ])
    expect(readStore().accounts.map((r: any) => r.id)).toEqual(['b'])
    const disabled = await a.revokeAccount({ accountId: 'b', disable: true })
    expect(disabled).toEqual({ accountId: 'b', outcome: 'revoked', removed: false })
    const [row] = await a.listAccounts()
    expect(row).toMatchObject({ id: 'b', enabled: false, refreshDead: true })
    // Dead now: a second revoke sends nothing and removes it.
    expect(await a.revokeAccount({ accountId: 'b' })).toMatchObject({ outcome: 'not_sent', removed: true })
    expect(revoked.length).toBe(2)
    expect(presented.length).toBe(0)
  })

  test('a failed revoke changes nothing; unknown and API-key rows are refused', async () => {
    seed([oauthRow('a')])
    const a = new AnthropicAuth({ storePath, tokenUrl, revokeUrl })
    revokeStatus = 503
    await expectCode(a.revokeAccount({ accountId: 'a' }), 'transient')
    const [row] = await a.listAccounts()
    expect(row).toMatchObject({ id: 'a', enabled: true, refreshDead: false })
    await expectCode(a.revokeAccount({ accountId: 'ghost' }), 'auth_required')
    await a.addApiKey({ label: 'key', key: API_KEY })
    await expectCode(a.revokeAccount({ accountId: 'key' }), 'config')
    // Test mode refuses the production revoke URL before a byte is sent.
    const prod = new AnthropicAuth({ storePath, revokeUrl: 'https://platform.claude.com/v1/oauth/token/revoke' })
    revokeStatus = 200
    await expectCode(prod.revokeAccount({ accountId: 'a' }), 'config')
    expect(revoked.length).toBe(1)
  })
})

// ---- API keys --------------------------------------------------------------
describe('API-key rows', () => {
  test('addApiKey stores the key; getApiKey hands it out; listAccounts shows a suffix only', async () => {
    seed([oauthRow('oauth', { expiresIn: 4 * HOUR })])
    const a = new AnthropicAuth({ storePath, tokenUrl })
    expect(await a.addApiKey({ label: 'Console', key: API_KEY })).toEqual({
      accountId: 'Console',
      status: 'added',
    })
    expect(await a.addApiKey({ key: API_KEY })).toEqual({ accountId: 'Console', status: 'already_present' })
    const rows = await a.listAccounts()
    const keyRow = rows.find((r: any) => r.id === 'Console')
    expect(keyRow).toMatchObject({ kind: 'api_key', apiKeySuffix: 'WXYZ', label: 'Console', enabled: true })
    expect(JSON.stringify(rows)).not.toContain(API_KEY)
    expect(await a.getApiKey()).toEqual({ apiKey: API_KEY, accountId: 'Console', label: 'Console' })
    expect((await a.getApiKey({ account: 'console' })).apiKey).toBe(API_KEY)
    // OAuth access and API keys stay separate.
    expect((await a.getAccessToken()).accountId).toBe('oauth')
    await expectCode(a.getApiKey({ account: 'oauth' }), 'auth_required')
    expect(await a.setAccountEnabled('Console', false)).toBe(true)
    await expectCode(a.getApiKey(), 'auth_required')
  })

  test('a malformed key is invalid_token and never stored', async () => {
    const a = new AnthropicAuth({ storePath, tokenUrl })
    await expectCode(a.addApiKey({ key: 'sk-ant-oat01-thisisanoauthtokennotakey00' }), 'invalid_token')
    await expectCode(a.addApiKey({ key: 'nope' }), 'invalid_token')
    expect(existsSync(storePath)).toBe(false)
    await expectCode(a.getApiKey(), 'auth_required')
  })
})

// ---- legacy adoption -------------------------------------------------------
function flatLegacy(path: string, rows: Array<{ uuid: string; refresh: string; enabled?: boolean; reason?: string }>) {
  mkdirSync(join(path, '..'), { recursive: true })
  writeFileSync(
    path,
    JSON.stringify({
      version: 1,
      active_index: 0,
      accounts: rows.map((r) => ({
        uuid: r.uuid,
        email: `${r.uuid}@example.com`,
        accessToken: 'sk-ant-oat01-legacylegacylegacylegacy00',
        refreshToken: r.refresh,
        expiresAt: Date.now() + HOUR,
        addedAt: Date.now() - DAY,
        scopes: ['user:inference'],
        enabled: r.enabled ?? true,
        ...(r.reason ? { disabledReason: r.reason } : {}),
      })),
    }),
  )
}

describe('legacy adoption', () => {
  test('legacyPaths are adopted once, dead rows skipped, and served', async () => {
    seed([oauthRow('main', { expiresIn: 4 * HOUR })])
    const legacy = join(dir, 'grok', 'anthropic-accounts.json')
    flatLegacy(legacy, [
      { uuid: 'jfc', refresh: 'sk-ant-ort01-legacylegacylegacylegacy00' },
      { uuid: 'dead', refresh: 'sk-ant-ort01-deadlegacydeadlegacydead00', enabled: false, reason: 'invalid_grant' },
    ])
    const a = new AnthropicAuth({ storePath, tokenUrl, legacyPaths: [legacy] })
    expect((await a.listAccounts()).map((r: any) => r.id)).toEqual(['main', 'jfc'])
    expect(readStore().migrated_from).toEqual([legacy])
    expect((await a.getAccessToken({ account: 'jfc' })).accountId).toBe('jfc')
    // Removed on purpose: never resurrected by a later pass.
    await a.removeAccount('jfc')
    expect((await a.listAccounts()).map((r: any) => r.id)).toEqual(['main'])
    // An explicit empty list adopts nothing.
    const other = join(dir, 'other.json')
    const b = new AnthropicAuth({ storePath: other, tokenUrl, legacyPaths: [] })
    expect(await b.listAccounts()).toEqual([])
    expect(existsSync(other)).toBe(false)
  })

  test('the default store discovers ~/.grok style files the way the crate does; others do not', async () => {
    const home = join(dir, 'home')
    flatLegacy(join(home, '.grok', 'anthropic-accounts.json'), [
      { uuid: 'grok', refresh: 'sk-ant-ort01-grokgrokgrokgrokgrokgrok00' },
    ])
    const saved = { file: process.env.ANTHROPIC_ACCOUNTS_FILE, home: process.env.HOME }
    delete process.env.ANTHROPIC_ACCOUNTS_FILE
    process.env.HOME = home
    try {
      const defaulted = new AnthropicAuth({ tokenUrl })
      expect(defaulted.storePath).toBe(join(home, '.anthropic-accounts', 'accounts.json'))
      expect((await defaulted.listAccounts()).map((r: any) => r.id)).toEqual(['grok'])
      const elsewhere = new AnthropicAuth({ storePath, tokenUrl })
      expect(await elsewhere.listAccounts()).toEqual([])
    } finally {
      process.env.ANTHROPIC_ACCOUNTS_FILE = saved.file
      process.env.HOME = saved.home
    }
  })
})

// ---- login -----------------------------------------------------------------
describe('login: per-login redirect/state, non-persisting exchange, identity', () => {
  test('startLogin takes a loopback redirectUri and state; the exchange uses both', async () => {
    const a = new AnthropicAuth({ storePath, tokenUrl, profileUrl })
    const state = 'loopbackstate_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-'
    const login = a.startLogin({ redirectUri: 'http://localhost:54545/callback', state })
    expect(login.state).toBe(state)
    const url = new URL(login.url)
    expect(url.searchParams.get('state')).toBe(state)
    expect(url.searchParams.get('redirect_uri')).toBe('http://localhost:54545/callback')
    const info = await a.completeLogin({
      loginId: login.loginId,
      callback: `http://localhost:54545/callback?code=the-code&state=${state}`,
    })
    expect(info.id).toBe('code@example.com')
    expect(exchanges.at(-1)).toMatchObject({ redirect_uri: 'http://localhost:54545/callback', state })
    // The handle's default redirect is untouched for the next login.
    expect(new URL(a.startLogin().url).searchParams.get('redirect_uri')).not.toBe(
      'http://localhost:54545/callback',
    )
    expect(() => a.startLogin({ state: 'bad state' })).toThrow(AnthropicAuthError)
    expect(() => a.startLogin({ redirectUri: 'not a url' })).toThrow(AnthropicAuthError)
  })

  test('exchangeCode returns an access token and stores nothing', async () => {
    const a = new AnthropicAuth({ storePath, tokenUrl })
    const login = a.startLogin({ mode: 'console' })
    const exchanged = await a.exchangeCode({ loginId: login.loginId, callback: `the-code#${login.state}` })
    expect(exchanged).toMatchObject({
      accessToken: 'sk-ant-oat01-exchangedexchangedexchang00',
      accountUuid: 'acct-code',
      email: 'code@example.com',
    })
    expect(exchanged.scopes).toContain('org:create_api_key')
    expect(JSON.stringify(exchanged)).not.toContain('sk-ant-ort01')
    expect(existsSync(storePath)).toBe(false)
    // Single use, and a tampered state is refused before any exchange.
    await expectCode(a.exchangeCode({ loginId: login.loginId, callback: 'the-code' }), 'auth_required')
    const second = a.startLogin({ mode: 'console' })
    await expect(a.exchangeCode({ loginId: second.loginId, callback: 'the-code#tampered' })).rejects.toBeInstanceOf(
      AnthropicAuthError,
    )
    expect(exchanges.length).toBe(1)
    // Input that is not a callback is refused before any exchange.
    const third = a.startLogin({ mode: 'console' })
    await expectCode(a.exchangeCode({ loginId: third.loginId, callback: 'not a callback' }), 'auth_required')
    expect(exchanges.length).toBe(1)
  })

  test('an anonymous grant is named from the profile endpoint', async () => {
    const a = new AnthropicAuth({ storePath, tokenUrl, profileUrl })
    const login = a.startLogin()
    const info = await a.completeLogin({ loginId: login.loginId, callback: `anon-code#${login.state}` })
    expect(info).toMatchObject({
      id: 'profile@example.com',
      email: 'profile@example.com',
      accountUuid: 'acct-profile',
      organizationUuid: 'org-profile',
    })
    expect(profileBearers).toEqual(['Bearer sk-ant-oat01-exchangedexchangedexchang00'])
  })

  test('backfillIdentities fills live unidentified rows only; test mode guards production', async () => {
    seed([
      oauthRow('live', { access: 'sk-ant-oat01-livelivelivelivelivelive00', expiresIn: HOUR }),
      oauthRow('expired', { access: 'sk-ant-oat01-expiredexpiredexpiredex00', refresh: 'sk-ant-ort01-expiredexpiredexpiredex00' }),
      oauthRow('known', { access: 'sk-ant-oat01-knownknownknownknownkno00', refresh: 'sk-ant-ort01-knownknownknownknownkno00', expiresIn: HOUR, uuid: 'acct-known' }),
    ])
    const a = new AnthropicAuth({ storePath, tokenUrl, profileUrl })
    expect(await a.backfillIdentities()).toEqual([
      { accountId: 'live', status: 'filled', email: 'profile@example.com' },
      { accountId: 'expired', status: 'no_live_access_token' },
      { accountId: 'known', status: 'already_identified' },
    ])
    expect(presented.length).toBe(0)
    const live = (await a.listAccounts()).find((r: any) => r.id === 'live')
    expect(live).toMatchObject({ email: 'profile@example.com', accountUuid: 'acct-profile' })
    const prod = new AnthropicAuth({ storePath, profileUrl: 'https://api.anthropic.com/api/oauth/profile' })
    await expectCode(prod.backfillIdentities(), 'config')
  })
})

// ---- error codes -----------------------------------------------------------
describe('error codes', () => {
  test('config is split: invalid_token for bad input, store_corrupt for a bad store', async () => {
    expect(ERROR_CODES).toEqual(
      expect.arrayContaining(['invalid_token', 'store_corrupt', 'config', 'transient']),
    )
    writeFileSync(storePath, '{ "accounts": [', { mode: 0o600 })
    const a = new AnthropicAuth({ storePath, tokenUrl })
    await expectCode(a.listAccounts(), 'store_corrupt')
    await expectCode(a.getAccessToken(), 'store_corrupt')
    await expectCode(
      a.importOAuthAccount({ accessToken: 'x', refreshToken: 'y', expiresAt: 0 }),
      'invalid_token',
    )
    expect(readFileSync(storePath, 'utf8')).toBe('{ "accounts": [')
  })
})
