# Claude Code auth/device porting guide

Source of truth: extracted/deobfuscated Claude Code 2.1.233 Linux x64 bundle at `/tmp/claude-code-latest/cli.deob.js` and `/tmp/claude-code-latest/AUDIT.md`.

## Goal

Port the observable authentication and device-security contracts into safe, reusable Rust modules. Preserve protocol bytes and state transitions, not minified JavaScript structure. Ordinary Messages API auth remains separate from Remote Control/Cowork device security.

## Mapping rules

| Source concept | Rust mapping |
|---|---|
| camelCase JSON | `snake_case` fields with explicit serde renames |
| millisecond timestamp | `DateTime<Utc>` serialized as epoch milliseconds in shared account data; RFC3339 strings only where wire format requires it |
| UUID string | validated `uuid::Uuid` at cryptographic boundaries; stored account IDs remain strings |
| Node `Buffer` concatenation | `Vec<u8>` with exact byte order and capacity |
| `crypto.generateKeyPairSync("ec", P-256)` | `p256::ecdsa::SigningKey` generated with `OsRng` |
| `crypto.sign("sha256", ..., ieee-p1363)` | `p256::ecdsa::signature::Signer`; `Signature::to_bytes()` (64-byte P1363) |
| PKCS#8/SPKI DER | RustCrypto `EncodePrivateKey` / `EncodePublicKey` |
| `fetch`/Axios | existing `reqwest::Client`, status/body normalization through crate errors |
| async localhost callback | Tokio `TcpListener`, bounded request/header sizes, fixed callback path, constant-time state check |
| keychain | optional `keyring` feature behind a small `SecretStore` interface; hardened file fallback always available |

## Security invariants

- `#![forbid(unsafe_code)]` remains mandatory.
- Never log access tokens, refresh tokens, trusted-device tokens, private keys, identity assertions, or raw credential documents.
- OAuth state is checked in constant time before returning a code.
- Callback server binds loopback only, accepts one valid completion, bounds every connection/request and total wait, ignores bounded wrong-method/path probes, and never follows redirects.
- Shared-store writes remain atomic, non-empty, non-symlinked, and user-only on Unix.
- WIF assertions are bounded to 16 KiB and error bodies are secret-redacted.
- Cowork bind preimage is byte-exact: domain || three 16-byte UUIDs || u64-be epoch milliseconds.
- Claude 2.1.233 CCH is xxHash64 seed `0x4d659218e32a3268`, masked to 20 bits, over a placeholder body whose model values are all emptied and integer max_tokens fields are all removed.
- Custom proxy credentials are never coerced into first-party Anthropic credentials.

## Module placement

```text
src/
  credentials/
    mod.rs          native Claude document + backend-neutral interface
    file.rs         hardened plaintext fallback
    keyring.rs      optional platform keyring adapter
    wif.rs          OIDC federation config/provider/cache
  device/
    mod.rs
    identity.rs     persistent global 32-byte device ID
    trusted.rs      trusted-device enrollment/header
    attestation.rs  server status normalization/filtering
    cowork.rs       P-256 registration + bind signing
  oauth_callback.rs localhost callback listener
```

Existing `oauth.rs`, `token.rs`, `store.rs`, `request.rs`, and `endpoints.rs` retain their current ownership.

## Semantic divergence ledger

| Area | Required behavior |
|---|---|
| base64 | Standard Base64 for DER/signatures; unpadded Base64url for PKCE/device IDs |
| ECDSA | Fixed 64-byte P1363, never DER signature encoding |
| timestamp | Same millisecond value in Cowork preimage and `issuedAt` |
| status threshold | `SERVICE_VOUCHED` always passes; threshold order is VERIFIED → VERIFIED_KEYLESS_DEVICE → VERIFIED_BY_GATE |
| token refresh | Preserve old refresh token when omitted; preserve identity metadata; persist optional refresh-token expiry |
| credential precedence | Explicit/shared current first; native import only when canonical shared state is absent or explicitly requested |

## Test parity ledger

| Source contract | Rust test |
|---|---|
| 32-byte PKCE/state | existing PKCE tests |
| callback state/path/bounds | `oauth_callback` tests |
| revoke body and permanent/transient errors | `oauth` tests |
| WIF assertion/body/cache | `credentials::wif` tests |
| native file schema/import | `credentials` tests |
| trusted-device request/header | `device::trusted` tests |
| attestation status/threshold | `device::attestation` exhaustive tests |
| P-256 DER registration | `device::cowork` tests |
| bind preimage/signature verification | fixed-vector + verify tests |
| global device ID persistence | `device::identity` tests |
| 2.1.233 CCH seed/preimage | `cch` native-oracle vector tests |

No port is complete until its corresponding test is present and `cargo test --all-features` passes.
