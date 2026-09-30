// Loaded by bunfig.toml before every test file. index.js snapshots these keys
// from `process.env` into the addon (Bun's `process.env` writes do not reach
// the native `getenv`), so they bind every AnthropicAuth handle a test makes:
//
// - ANTHROPIC_OAUTH_TEST_MODE=1: any OAuth call to a non-loopback host fails
//   with code `config` before a byte is sent.
// - every OAuth URL defaults to port 9 on loopback (discard; nothing listens),
//   so a handle without an explicit `tokenUrl` fails `transient` locally.
// - the default store and HOME live in a throwaway directory.
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export const DEAD_LOOPBACK = 'http://127.0.0.1:9'

const home = mkdtempSync(join(tmpdir(), 'anthropic-napi-preload-'))
Object.assign(process.env, {
  ANTHROPIC_OAUTH_TEST_MODE: '1',
  ANTHROPIC_OAUTH_TOKEN_URL: `${DEAD_LOOPBACK}/v1/oauth/token`,
  ANTHROPIC_OAUTH_REVOKE_URL: `${DEAD_LOOPBACK}/v1/oauth/token/revoke`,
  ANTHROPIC_OAUTH_AUTHORIZE_URL: `${DEAD_LOOPBACK}/cai/oauth/authorize`,
  ANTHROPIC_OAUTH_CONSOLE_AUTHORIZE_URL: `${DEAD_LOOPBACK}/oauth/authorize`,
  ANTHROPIC_OAUTH_REDIRECT_URI: `${DEAD_LOOPBACK}/oauth/code/callback`,
  ANTHROPIC_OAUTH_USAGE_URL: `${DEAD_LOOPBACK}/api/oauth/usage`,
  ANTHROPIC_OAUTH_PROFILE_URL: `${DEAD_LOOPBACK}/api/oauth/profile`,
  ANTHROPIC_BASE_URL: DEAD_LOOPBACK,
  HOME: home,
  ANTHROPIC_ACCOUNTS_FILE: join(home, 'accounts.json'),
})
