// Build the native addon with plain cargo and place it next to index.js as
// `anthropic-napi.<platform>-<arch>.node`, the name the loader looks for.
//
//   node scripts/build.mjs            # release
//   node scripts/build.mjs --debug    # debug
//
// Honours CARGO_TARGET_DIR. Uses whatever toolchain `cargo` resolves to.
import { execFileSync } from 'node:child_process'
import { copyFileSync, existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const here = dirname(fileURLToPath(import.meta.url))
const pkg = resolve(here, '..')
const workspace = resolve(pkg, '..')
const debug = process.argv.includes('--debug')
const profile = debug ? 'debug' : 'release'

execFileSync(
  'cargo',
  ['build', '-p', 'anthropic-napi', ...(debug ? [] : ['--release'])],
  { cwd: workspace, stdio: 'inherit' },
)

const targetDir = process.env.CARGO_TARGET_DIR
  ? resolve(process.env.CARGO_TARGET_DIR)
  : join(workspace, 'target')
const artifact = {
  linux: 'libanthropic_napi.so',
  darwin: 'libanthropic_napi.dylib',
  win32: 'anthropic_napi.dll',
}[process.platform]
if (!artifact) throw new Error(`unsupported platform ${process.platform}`)
const from = join(targetDir, profile, artifact)
if (!existsSync(from)) throw new Error(`build output not found: ${from}`)
const to = join(pkg, `anthropic-napi.${process.platform}-${process.arch}.node`)
copyFileSync(from, to)
console.log(`anthropic-napi: ${from} -> ${to}`)
