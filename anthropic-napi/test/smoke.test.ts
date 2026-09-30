// Smoke test for the native binding. Runs entirely against a temp store and
// local mock servers; it never touches ~/.anthropic-accounts or any real
// Anthropic endpoint. Run with `bun test test/` after `npm run build`.
import { afterAll, beforeAll, beforeEach, describe, expect, test } from 'bun:test'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const sandbox = mkdtempSync(join(tmpdir(), 'anthropic-napi-smoke-'))
// Belt and braces: even a default-constructed handle stays in the sandbox.
process.env.ANTHROPIC_ACCOUNTS_FILE = join(sandbox, 'default-accounts.json')
process.env.HOME = sandbox

const { AnthropicAuth, AnthropicAuthError } = require('../index.js')

const HOUR = 3_600_000
const DAY = 24 * HOUR
const OLD_REFRESH = 'sk-ant-ort01-seededseededseededseeded00'
const OLD_ACCESS = 'sk-ant-oat01-seededseededseededseeded00'
const DEAD_REFRESH = 'sk-ant-ort01-deaddeaddeaddeaddeaddead00'

// ---- mock token endpoint ---------------------------------------------------
const presented: string[] = []
const codeExchanges: Array<Record<string, string>> = []
let rotation = 0
const tokenServer = Bun.serve({
  port: 0,
  async fetch(req) {
    const url = new URL(req.url)
    if (req.method !== 'POST' || url.pathname !== '/v1/oauth/token') {
      return new Response('not found', { status: 404 })
    }
    const body = (await req.json()) as Record<string, string>
    if (body.grant_type === 'refresh_token') {
      presented.push(body.refresh_token)
      if (body.refresh_token.startsWith('sk-ant-ort01-dead')) {
        return Response.json(
          { error: 'invalid_grant', error_description: 'Refresh token not found or invalid' },
          { status: 400 },
        )
      }
      rotation += 1
      return Response.json({
        access_token: `sk-ant-oat01-rotated${rotation}rotatedrotatedrot00`,
        refresh_token: `sk-ant-ort01-rotated${rotation}rotatedrotatedrot00`,
        expires_in: 28_800,
        refresh_token_expires_in: 30 * 86_400,
        scope: 'user:inference user:profile',
      })
    }
    if (body.grant_type === 'authorization_code') {
      codeExchanges.push(body)
      if (body.code !== 'the-code') return Response.json({ error: 'invalid_grant' }, { status: 400 })
      return Response.json({
        access_token: 'sk-ant-oat01-loginloginloginloginlogin00',
        refresh_token: 'sk-ant-ort01-loginloginloginloginlogin00',
        expires_in: 28_800,
        scope: 'user:inference user:profile',
        account: { uuid: 'acct-login', email_address: 'login@example.com' },
        organization: { uuid: 'org-login' },
      })
    }
    return Response.json({ error: 'unsupported_grant_type' }, { status: 400 })
  },
})
const tokenUrl = `http://127.0.0.1:${tokenServer.port}/v1/oauth/token`

// ---- mock Messages endpoint ------------------------------------------------
const bearers: string[] = []
const messagesServer = Bun.serve({
  port: 0,
  async fetch(req) {
    const auth = req.headers.get('authorization') ?? ''
    bearers.push(auth)
    if (!auth.startsWith('Bearer sk-ant-oat01-rotated')) {
      return Response.json({ type: 'error', error: { type: 'authentication_error' } }, { status: 401 })
    }
    return Response.json({
      type: 'message',
      role: 'assistant',
      content: [{ type: 'text', text: 'pong' }],
    })
  },
})
const messagesUrl = `http://127.0.0.1:${messagesServer.port}/v1/messages`

afterAll(() => {
  tokenServer.stop(true)
  messagesServer.stop(true)
  rmSync(sandbox, { recursive: true, force: true })
})

// ---- store helpers ---------------------------------------------------------
let storePath = ''
let n = 0

function oauthRow(
  id: string,
  opts: { access?: string; refresh?: string; expiresIn?: number; refreshExpiresIn?: number } = {},
) {
  const now = Date.now()
  return {
    id,
    email: `${id}@example.com`,
    credential: {
      type: 'oauth',
      access: opts.access ?? OLD_ACCESS,
      refresh: opts.refresh ?? OLD_REFRESH,
      expires_at: now + (opts.expiresIn ?? -HOUR),
      refresh_expires_at: now + (opts.refreshExpiresIn ?? 20 * DAY),
      scopes: ['user:inference', 'user:profile'],
      host_only_field: 'kept',
    },
    enabled: true,
    created_at: new Date(now - DAY).toISOString(),
    opencode_sidecar: { pinned: true },
  }
}

function seed(accounts: unknown[], extra: Record<string, unknown> = {}) {
  writeFileSync(storePath, JSON.stringify({ version: 1, accounts, ...extra }, null, 2), {
    mode: 0o600,
  })
}

function readStore(): any {
  return JSON.parse(readFileSync(storePath, 'utf8'))
}

function auth() {
  return new AnthropicAuth({ storePath, tokenUrl })
}

beforeEach(() => {
  n += 1
  storePath = join(sandbox, `accounts-${n}.json`)
  presented.length = 0
  bearers.length = 0
})

async function expectCode(promise: Promise<unknown>, code: string) {
  let caught: any
  try {
    await promise
  } catch (error) {
    caught = error
  }
  expect(caught).toBeInstanceOf(AnthropicAuthError)
  expect(caught.code).toBe(code)
  expect(String(caught.message)).not.toContain('sk-ant-ort01')
  return caught
}

// ---- tests -----------------------------------------------------------------
describe('getAccessToken', () => {
  test('refreshes an expired account, persists the rotation, never exposes the refresh token', async () => {
    seed([oauthRow('main')], { writer: { name: 'another-tool' } })
    const a = auth()

    const token = await a.getAccessToken()
    expect(token.source).toBe('refreshed')
    expect(token.accountId).toBe('main')
    expect(token.email).toBe('main@example.com')
    expect(token.accessToken).toMatch(/^sk-ant-oat01-rotated\d+/)
    expect(token.expiresAt).toBeGreaterThan(Date.now() + 7 * HOUR)
    // Only the store's token was spent, once.
    expect(presented).toEqual([OLD_REFRESH])
    // No refresh token in what JS receives.
    expect(Object.keys(token).sort()).toEqual(
      ['accessToken', 'accountId', 'email', 'expiresAt', 'source'].sort(),
    )
    expect(JSON.stringify(token)).not.toContain('sk-ant-ort01')

    // Persisted, with foreign fields intact and no leftover claim.
    const stored = readStore()
    const row = stored.accounts[0]
    expect(row.credential.access).toBe(token.accessToken)
    expect(row.credential.refresh).toMatch(/^sk-ant-ort01-rotated/)
    expect(row.credential.refresh).not.toBe(OLD_REFRESH)
    expect(row.refresh_lease).toBeUndefined()
    expect(row.credential.host_only_field).toBe('kept')
    expect(row.opencode_sidecar).toEqual({ pinned: true })
    expect(stored.writer).toEqual({ name: 'another-tool' })

    // The bearer works against the (mock) Messages API.
    const response = await fetch(messagesUrl, {
      method: 'POST',
      headers: { authorization: `Bearer ${token.accessToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'claude-test', max_tokens: 4, messages: [] }),
    })
    expect(response.status).toBe(200)
    expect(((await response.json()) as any).content[0].text).toBe('pong')

    // Live now: served from the store without another spend.
    const again = await a.getAccessToken()
    expect(again.source).toBe('store')
    expect(again.accessToken).toBe(token.accessToken)
    expect(presented.length).toBe(1)

    const listed = await a.listAccounts()
    expect(listed.length).toBe(1)
    expect(listed[0].accessLive).toBe(true)
    expect(listed[0].refreshDead).toBe(false)
    expect(listed[0].current).toBe(true)
    expect(listed[0].lastRefreshedAt).toBeGreaterThan(Date.now() - 60_000)
    const listedJson = JSON.stringify(listed)
    expect(listedJson).not.toContain('sk-ant-ort01')
    expect(listedJson).not.toContain('sk-ant-oat01')
  })

  test('a revoked refresh token is invalid_grant, recorded dead, and never re-presented', async () => {
    seed([oauthRow('dead', { refresh: DEAD_REFRESH })])
    const a = auth()
    await expectCode(a.getAccessToken(), 'invalid_grant')
    expect(presented).toEqual([DEAD_REFRESH])
    const [info] = await a.listAccounts()
    expect(info.refreshDead).toBe(true)
    expect(info.lastError).toBe('invalid_grant')
    await expectCode(a.getAccessToken(), 'invalid_grant')
    expect(presented.length).toBe(1)
  })

  test('rotates past a dead login to a healthy one', async () => {
    const secondDead = 'sk-ant-ort01-deadtwodeadtwodeadtwodead00'
    seed([
      oauthRow('dead', { refresh: secondDead }),
      oauthRow('ok', { access: 'sk-ant-oat01-okokokokokokokokokokokok00', refresh: 'sk-ant-ort01-okokokokokokokokokokokok00' }),
    ])
    const token = await auth().getAccessToken()
    expect(token.accountId).toBe('ok')
    expect(presented).toEqual([secondDead, 'sk-ant-ort01-okokokokokokokokokokokok00'])
  })

  test('typed errors: auth_required, quota_reserve, config', async () => {
    seed([oauthRow('main', { expiresIn: 4 * HOUR })])
    const a = auth()
    await expectCode(a.getAccessToken({ account: 'nobody@example.com' }), 'auth_required')
    await expectCode(a.getAccessToken({ reservePct: 150 }), 'config')
    expect(await a.recordQuota({ accountId: 'main', fiveHourPercent: 95, sevenDayPercent: 10 })).toBe('main')
    await expectCode(a.getAccessToken({ reservePct: 90 }), 'quota_reserve')
    const ok = await a.getAccessToken({ reservePct: 99 })
    expect(ok.source).toBe('store')
    expect(() => new AnthropicAuth({ storePath: '' })).toThrow(AnthropicAuthError)

    const empty = new AnthropicAuth({ storePath: join(sandbox, 'missing.json'), tokenUrl })
    await expectCode(empty.getAccessToken(), 'auth_required')
  })

  test('rate limits and quota headers are recorded against the right row', async () => {
    seed([
      oauthRow('a', { expiresIn: 4 * HOUR, access: 'sk-ant-oat01-aaaaaaaaaaaaaaaaaaaaaaaa00', refresh: 'sk-ant-ort01-aaaaaaaaaaaaaaaaaaaaaaaa00' }),
      oauthRow('b', { expiresIn: 4 * HOUR, access: 'sk-ant-oat01-bbbbbbbbbbbbbbbbbbbbbbbb00', refresh: 'sk-ant-ort01-bbbbbbbbbbbbbbbbbbbbbbbb00' }),
    ], { current: 'a' })
    const a = auth()
    expect(await a.markRateLimited({ accountId: 'a', retryAfterMs: 60_000 })).toBe(true)
    expect(await a.markRateLimited({ accountId: 'ghost', retryAfterMs: 1 })).toBe(false)
    const next = await a.getAccessToken()
    expect(next.accountId).toBe('b')
    const landed = await a.recordQuotaHeaders({
      accessToken: next.accessToken,
      headers: {
        'anthropic-ratelimit-unified-5h-utilization': '0.42',
        'anthropic-ratelimit-unified-7d-utilization': '0.10',
      },
    })
    expect(landed).toBe('b')
    const rows = await a.listAccounts()
    const b = rows.find((r: any) => r.id === 'b')
    expect(b.quota.fiveHourPercent).toBeCloseTo(42)
    expect(rows.find((r: any) => r.id === 'a').rateLimitedUntil).toBeGreaterThan(Date.now())
    expect(presented.length).toBe(0)
  })
})

describe('login and import', () => {
  test('PKCE login exchanges the code in Rust and stores the account', async () => {
    seed([oauthRow('main', { expiresIn: 4 * HOUR })])
    const a = auth()
    const login = a.startLogin({ loginHint: 'login@example.com' })
    expect(Object.keys(login).sort()).toEqual(['loginId', 'state', 'url'])
    const url = new URL(login.url)
    expect(url.searchParams.get('state')).toBe(login.state)
    expect(url.searchParams.get('code_challenge_method')).toBe('S256')
    expect(url.searchParams.get('login_hint')).toBe('login@example.com')

    const info = await a.completeLogin({ loginId: login.loginId, callback: `the-code#${login.state}` })
    expect(info.email).toBe('login@example.com')
    expect(info.accountUuid).toBe('acct-login')
    expect(info.organizationUuid).toBe('org-login')
    expect(JSON.stringify(info)).not.toContain('sk-ant')
    expect(codeExchanges.at(-1)?.code_verifier?.length).toBeGreaterThanOrEqual(43)
    expect(codeExchanges.at(-1)?.state).toBe(login.state)
    const rows = readStore().accounts
    expect(rows.map((r: any) => r.id)).toEqual(['main', 'login@example.com'])
    // The login id is single-use; a tampered state is refused.
    await expectCode(a.completeLogin({ loginId: login.loginId, callback: `the-code#${login.state}` }), 'auth_required')
    const second = a.startLogin()
    let tampered: any
    try {
      await a.completeLogin({ loginId: second.loginId, callback: 'the-code#not-the-state' })
    } catch (error) {
      tampered = error
    }
    expect(tampered).toBeInstanceOf(AnthropicAuthError)
  })

  test('import moves a host credential into the store; the store copy wins', async () => {
    seed([oauthRow('main', { expiresIn: 4 * HOUR })])
    const a = auth()
    const imported = await a.importOAuthAccount({
      label: 'sidecar',
      accessToken: 'sk-ant-oat01-sidecarsidecarsidecarside00',
      refreshToken: 'sk-ant-ort01-sidecarsidecarsidecarside00',
      expiresAt: Date.now() + HOUR,
      accountUuid: 'acct-sidecar',
      email: 'sidecar@example.com',
    })
    expect(imported).toEqual({ accountId: 'sidecar', status: 'added' })
    const again = await a.importOAuthAccount({
      accessToken: 'sk-ant-oat01-sidecarsidecarsidecarside00',
      refreshToken: 'sk-ant-ort01-sidecarsidecarsidecarside00',
      expiresAt: Date.now() + HOUR,
    })
    expect(again.status).toBe('already_present')
    const stale = await a.importOAuthAccount({
      accessToken: 'sk-ant-oat01-olderolderolderolderolde00',
      refreshToken: 'sk-ant-ort01-olderolderolderolderolde00',
      expiresAt: Date.now() - HOUR,
      accountUuid: 'acct-sidecar',
    })
    expect(stale).toEqual({ accountId: 'sidecar', status: 'kept' })
    expect(readStore().accounts.find((r: any) => r.id === 'sidecar').credential.refresh).toBe(
      'sk-ant-ort01-sidecarsidecarsidecarside00',
    )
    await expectCode(
      a.importOAuthAccount({ accessToken: 'x', refreshToken: 'y', expiresAt: 0 }),
      'config',
    )
  })
})

describe('keepAliveOnce and 401 recovery', () => {
  test('keeps an idle account with a near refresh expiry alive, once', async () => {
    seed([
      oauthRow('idle', { refreshExpiresIn: 3 * DAY }),
      oauthRow('busy', { expiresIn: 4 * HOUR, access: 'sk-ant-oat01-busybusybusybusybusybu00', refresh: 'sk-ant-ort01-busybusybusybusybusybu00' }),
    ])
    const a = auth()
    const report = await a.keepAliveOnce({ spacingMs: 0 })
    expect(report.lease).toBe('acquired')
    expect(report.refreshed).toEqual([{ accountId: 'idle', reason: 'refresh_expiring' }])
    expect(report.skipped).toContainEqual({ accountId: 'busy', reason: 'session_live' })
    expect(presented).toEqual([OLD_REFRESH])
    expect(readStore().keepalive).toBeUndefined()
    const second = await a.keepAliveOnce({ spacingMs: 0 })
    expect(second.refreshed).toEqual([])
    expect(presented.length).toBe(1)
  })

  test('a 401 on a store bearer earns one claimed refresh and a retry', async () => {
    seed([oauthRow('main', { expiresIn: 4 * HOUR })])
    const a = auth()
    const unknown = await a.handleUnauthorized({ accessToken: 'sk-ant-oat01-notinthestorenotinthe00' })
    expect(unknown.retry).toBe(false)
    const recovered = await a.handleUnauthorized({ accessToken: OLD_ACCESS })
    expect(recovered.retry).toBe(true)
    expect(recovered.token.accessToken).toMatch(/^sk-ant-oat01-rotated/)
    expect(JSON.stringify(recovered)).not.toContain('sk-ant-ort01')
    expect(presented).toEqual([OLD_REFRESH])
  })
})
