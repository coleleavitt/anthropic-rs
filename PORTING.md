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

## 2.1.280 / TS sync f74d736

Source of truth: anthropic-auth merge `f74d736` (`sync/upstream-2026-09-26`), `packages/core/src`, and the merge decisions at the top of `docs/TS_SYNC_2026-09-26.md`. Fixed vectors were produced by running the merged TS under Bun.

| Merge decision | Rust | Tests |
|---|---|---|
| cch: upstream canonical signing is the default | `cch::sign_request_body` = TS `signRequestBody` (TS pattern with header as `system[0]`, reset slot, top-level `model:""` / no `max_tokens`, `JSON.stringify`-exact re-serialization via `cch::js_json_stringify`, xxHash64 seed `0x4d659218e32a3268`, 20-bit mask). `CchMode` = `Native` (default) / `Literal` / `Hmac` / `Xxhash`, env `ANTHROPIC_AUTH_CCH_MODE`. The global 2.1.233 transform is kept as `sign_request_body_2_1_233` for diagnostics only. | `cch::tests::*` |
| Billing header order and lineage | `billing::build_billing_header_value`: `cc_workload`, `cc_is_subagent`, then `cc_prev_req` (`^req_[A-Za-z0-9_-]{8,128}$`), `cc_prompt_id` (UUID v1–8, variant 8–b). First user text: `<command-name>` block, else the last non-empty text block; `FirstUserTextTracker` pins it per session (LRU 1000). `strip_billing_lineage_fields` / `strip_billing_lineage_from_body`. | `billing::tests::*` |
| Betas | `claude_code::CLAUDE_CODE_{FULL_AGENT,STRUCTURED_OUTPUT,BASE}_BETAS` = upstream tuples (base has no `claude-code-20250219`); then fast, `effort-2025-11-24` whenever `output_config.effort` is present, `context-1m` unless suppressed, then extras. Fork headers kept; env-forwarded headers via `claude_code_env_headers`. | `beta_selection_matches_merged_ts_vectors`, `env_forwarded_headers_are_encoded_and_optional` |
| Device identity | `claude_code::derive_claude_code_device_id(secret, cache_key)` = `sha256_hex(secret + "\0" + key)`, keys from `claude_code_identity_cache_key` (`identity:<id>` / `compat:<token>`); `DeviceId::account_device_id`. The installation id is never sent directly. | `per_account_device_id_matches_merged_ts`, `account_device_ids_are_stable_across_restarts_and_distinct` |
| Models | `is_claude_opus_5_model` excludes `claude-opus-5-5`; `is_claude_opus_5_family_model` for shared behavior (summarized adaptive injection). Family predicates strip one trailing `[1m]` (`normalize_anthropic_model_id`), exact-case like upstream. Fast mode = `claude-opus-4-8*` / `claude-opus-5*`. Opus 5.5 pricing 4/20/0.2, cache write 5m 5, 1h 8. | `family_predicates_match_merged_ts_vectors`, `fast_mode_eligibility_matches_upstream_table`, `opus_5_5_specifications_and_pricing` |
| Transient network codes | `backoff::TRANSIENT_NETWORK_ERROR_CODES` = the 18-code union; `BrokenPipe` / `NetworkDown` I/O kinds. | `messages_are_redacted_and_network_codes_recognized` |
| Killswitch 429 | `killswitch::killswitch_block_response`: 429, `retry-after: 60`, `x-should-retry: false`. | `synthesized_block_is_not_retryable` |
| Tombstones never mirrored | `Account::replace_oauth_tokens` refuses `claustrum-tombstone:v1:*`. | `replacing_oauth_tokens_keeps_account_email_in_sync` |

Not applicable here: the account-lineage handoff (the Rust store keys accounts by a stable id and never had the fork's refresh-fingerprint handoff); the pre-send primary quota probe and scoped custody (no main/fallback split, no Claustrum client); bootstrap `/api/claude_cli/bootstrap` lookups. Excluded by decision: the refusal / content-filter / surrogate / session-heat / context-sanitizer layer, OpenCode/Pi host glue, and the Claustrum custody client.

## Store hardening (doc 23, `store-hardening`)

Source: ckl `docs/replacement/23-oauth-store-invalid-grant.md` §6–§7. Here the Rust crate deliberately *diverges* from the current TS core (`shared-account-adapter.ts`, `accounts.ts`) where the TS behavior produced stale `invalid_grant` flags and double spends; the napi binding is how the TS plugin adopts the Rust behavior.

| Behavior | Rust | Tests |
|---|---|---|
| Row updates keep unknown fields (TS `fallbackAccountToShared` rebuilt rows and dropped `quota`, fingerprint, lease) | `Account` wire form with `extra` / `credential_extra`; `AccountStore::extra` | `row_updates_preserve_every_field_they_do_not_own`, `unknown_row_and_credential_fields_survive_a_round_trip` |
| `last_error` bound to a token; stale flags self-clear | `last_error_fingerprint`, `Account::current_error`, `clear_stale_error` in every `mutate` | `a_stale_unbound_invalid_grant_flag_clears_itself`, `a_locked_write_clears_stale_flags_and_keeps_real_ones` |
| Dead only on HTTP 400 `error=invalid_grant` for the token the row still holds (TS matched `message.includes`) | `Error::is_invalid_grant`, `RevocationOrigin` | `only_a_400_invalid_grant_marks_the_token_dead`, `invalid_grant_on_a_token_the_store_no_longer_holds_marks_nothing` |
| Spend only the store's token; fail closed on unknown tokens (TS claim failed open) | `refresh_shared` `Located`, `allow_unshared` | `a_stale_caller_token_is_never_spent_the_stores_token_is`, `unknown_token_adopts_a_live_rotated_shared_credential` |
| Token call bounded inside the claim | `OAUTH_HTTP_TIMEOUT`, `refresh_deadline`, `commit_refresh_before_expiry` | `the_default_client_gives_up_before_the_refresh_claim_lapses`, `a_stalled_token_call_is_cut_off_inside_the_claim_and_never_committed` |
| Legacy `invalid_grant` rows not imported | `legacy.rs` | `never_imports_a_row_disabled_with_invalid_grant` |
| One keep-alive per machine replaces the TS background refresher | `keepalive` | `two_concurrent_passes_do_the_work_once` |
| Coarse host API | `access::get_access_token`, `anthropic-napi` | `access::tests::*`, `anthropic-napi/test/smoke.test.ts` |
