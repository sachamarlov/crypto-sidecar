# 0016 — Tauri sidecar IPC: per-launch token, session model, anti-oracle layer

- Status: accepted
- Date: 2026-04-27
- Deciders: @sachamarlov, Claude Opus 4.7 (1M context)
- Tags: [api, security, threat-model, sidecar]
- Related: ADR-0001 (Tauri 2 + Python sidecar), ADR-0011 (cross-platform
  database encryption), ADR-0015 (anti-oracle on stderr).
- Tracks: spec 000-tauri-sidecar (Phase G).

## Context

Phase G ships a FastAPI sidecar bundled with the Tauri shell as an
external binary. The shell spawns the sidecar at app launch and
communicates with it over loopback HTTP. Every cryptographic
operation now exposed by the GUI (encrypt, decrypt, share, accept,
secure-delete, audit) crosses that boundary.

Before writing a single router, we must lock in the contract that
governs that boundary. The decisions here are **not** local to one
function — they shape every endpoint, every test, and every threat
model entry. Splitting them across PRs would let later choices
silently contradict earlier ones.

Adversaries we explicitly model on this boundary (cf.
`docs/THREAT_MODEL.md` §3 + §4.3):

- **AD-1** Remote attacker over network — cannot reach the loopback
  socket; out of scope for the listener.
- **AD-2** Local non-privileged process — can `netstat` the open
  port, can read filesystem, can attempt to talk to
  `127.0.0.1:<port>` directly. **This is the realistic adversary on
  this boundary.**
- **AD-4** Curious developer / packager — sees the binary, reads
  the code, reads logs.

The contract must defeat AD-2 without making the legitimate
loopback request from the Tauri shell more expensive than necessary.

## Decision drivers

1. The sidecar is single-tenant and short-lived (one process per
   GUI launch). No user / role separation inside it.
2. The shell and the sidecar live on the same host with the same
   filesystem permissions; TLS adds no confidentiality benefit on
   loopback (kernel never sees the traffic on a remote NIC) but
   does add boot latency and signature management overhead.
3. The CLI / TUI already establish a uniform anti-oracle stance on
   decrypt failures (ADR-0015). The HTTP layer must propagate that
   stance — no router may surface a richer error than the underlying
   `core` does.
4. The vault admin password unlocks the entire DB-encryption surface
   (ADR-0011 column-level fallback). Holding it as long as a Tauri
   tab is open is a memory-residency risk; auto-locking after idle
   is non-negotiable. Auto-lock minutes is already a `Settings`
   field (`auto_lock_minutes: int = 15`).
5. AD-2 can attempt a brute-force unlock against the loopback API
   without any of the OS-level rate limiting that protects e.g. SSH.
   We must add an HTTP-layer rate limit ourselves.

## Considered options

### A. Authentication transport

| Option                                                                                             | Verdict                                                                                                                           |
| -------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| **Per-launch session token (32 random bytes), `X-GuardiaBox-Token` header, `hmac.compare_digest`** | Adopted.                                                                                                                          |
| OS-level UDS / named pipe                                                                          | Rejected: cross-platform inconsistency (different paths on Linux/macOS/Windows), Tauri's HTTP plugin already speaks HTTP cleanly. |
| Mutual TLS with self-signed cert                                                                   | Rejected: cert generation + trust-store config + boot latency for a defence we don't need on loopback.                            |
| JWT / OAuth                                                                                        | Rejected: no third-party identity provider, single-tenant. JWT verification on every call is dead weight.                         |

### B. Vault session model

| Option                                                                                                                                                                                                         | Verdict                                                                                                                                                |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **In-memory `SessionStore` keyed by random `session_id` (32 octets), holding the `vault_admin_key` and per-user `vault_key`s in `bytearray`s, with TTL = `auto_lock_minutes` and zero-fill on close / expiry** | Adopted.                                                                                                                                               |
| Re-derive the admin key on every router call (no session)                                                                                                                                                      | Rejected: PBKDF2 600 000 iterations would add ~250 ms per request — fails NFR-1 / NFR-3 under load.                                                    |
| Persist session token to disk encrypted                                                                                                                                                                        | Rejected: a re-launch should require re-authentication; persisting reduces this guarantee.                                                             |
| Single global admin key in app state (no `session_id` indirection)                                                                                                                                             | Rejected: the indirection is what makes `lock` and `change_password` cheap (drop one map entry, zero-fill its buffers) without restarting the process. |

### C. Anti-oracle propagation

| Option                                                                                                                                                                                                                                                                                          | Verdict                                                                                                                                                                         |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **HTTP 422 with constant body `{"detail": "decryption failed"}` for every post-KDF decrypt failure (`DecryptionError` ∪ `IntegrityError`); pre-KDF failures (`InvalidContainerError`, `UnsupportedVersionError`, `UnknownKdfError`, `WeakKdfParametersError`) keep their distinct 4xx classes** | Adopted (mirrors ADR-0015).                                                                                                                                                     |
| Use HTTP 401 / 403 to discriminate auth-failure vs format-failure                                                                                                                                                                                                                               | Rejected: 401 / 403 already mean "auth missing/forbidden" at the framework level (token middleware) — overloading them at the application layer would muddy the threat surface. |
| Wrap every error in 500                                                                                                                                                                                                                                                                         | Rejected: 500 is reserved for genuine server bugs (panic, OS error). Conflating them would hide real defects.                                                                   |

### D. Rate limiting

| Option                                                                                                                                        | Verdict                                                                                                                                            |
| --------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`slowapi` (built on `limits`), per-IP key (always `127.0.0.1` here so effectively per-process), differentiated buckets per endpoint group** | Adopted.                                                                                                                                           |
| `fastapi-limiter` (Redis-backed)                                                                                                              | Rejected: Redis dependency is unacceptable for an offline-first product (NFR foundational).                                                        |
| No rate limit                                                                                                                                 | Rejected: leaves AD-2 free to brute-force the unlock endpoint at 50k req/s. PBKDF2 mitigates the cost on each attempt but does not bound the rate. |
| Custom asyncio semaphore                                                                                                                      | Rejected: re-implements `slowapi`.                                                                                                                 |

Bucket values:

| Endpoint group                                                     | Limit          |
| ------------------------------------------------------------------ | -------------- |
| `/vault/unlock`, `/users/{id}/unlock`                              | **5 / minute** |
| `/encrypt`, `/decrypt`, `/share`, `/accept`, `/secure-delete`      | 60 / minute    |
| `/users` CRUD, `/init`                                             | 30 / minute    |
| `/audit`, `/inspect`, `/doctor`, `/healthz`, `/readyz`, `/version` | 600 / minute   |

The 5/min on unlock is the load-bearing one: at PBKDF2 600 000
iterations and 5 attempts/minute, an attacker who can guess one
password per attempt ramps a typical `zxcvbn ≥ 3` (≈ 35 bits of
entropy) at `2^35 / (5 × 60 × 24 × 365) ≈ 13 000 years`. The other
buckets are operational, not security floors.

### E. Progress streaming

| Option                                                                                          | Verdict                                                                                                                    |
| ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **WebSocket `/api/v1/stream` per session, query-string auth (`?token=&session=`), JSON frames** | Adopted.                                                                                                                   |
| Server-Sent Events                                                                              | Rejected: unidirectional; future cancellations and chunked uploads need bidirectional.                                     |
| Long-polling                                                                                    | Rejected: O(n) connection overhead, sub-optimal latency for a 60 fps progress bar.                                         |
| No streaming, sync responses                                                                    | Rejected: a 5-minute encrypt would freeze the UI. NFR-3 cold-start budget would still hold but in-flight UX would be poor. |

### F. TLS on loopback

Decision: **no TLS**. The Linux kernel routes 127.0.0.1 traffic
without ever touching a NIC; the same applies to the Windows
loopback adapter. An attacker capable of sniffing this traffic has
already escalated to kernel level (out of scope). TLS would add
boot latency (cert generation each launch) and certificate trust
plumbing for zero gain.

A defence-in-depth alternative — HMAC-over-body — is **not**
adopted today because the request-payload integrity is already
covered by the underlying AEAD (decrypt requires the password to
authenticate; encrypt cannot be tampered with in flight without
detection at decrypt time). Re-evaluate if the sidecar ever binds
beyond loopback.

### G. Bind hard-coding

`SidecarSettings.host: Literal["127.0.0.1"]` (already in
`config.py`). The literal type makes it impossible to launch with
`0.0.0.0` even by env-var override — the pydantic validator would
refuse. A dedicated test (`tests/integration/test_sidecar_bind_security.py`)
greps the codebase for `"0.0.0.0"` to catch any regression.

### H. Schemas: strict & frozen

- All Pydantic v2 models use
  `model_config = ConfigDict(strict=True, extra="forbid", frozen=True)`.
- Password fields use `pydantic.SecretStr` so `repr(model)` and
  `model.model_dump()` redact the value automatically.
- `Path` fields are validated post-hoc by the router (`resolve_within`
  inside the `Settings.data_dir` root) — the schema only checks
  surface shape.

### I. CORS

Disabled. The only legitimate caller is the Tauri shell on the same
origin via the loopback URL it discovered through the handshake.
WebView2's CSP already restricts `connect-src` to
`http://127.0.0.1:* ws://127.0.0.1:*` (cf. `tauri.conf.json`).

## Decision (summary)

| Concern              | Choice                                                                                                                                             |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bind                 | `127.0.0.1` only, hard-coded `Literal` in settings, security test in CI.                                                                           |
| Auth (transport)     | `X-GuardiaBox-Token` header, 32 random octets generated per launch via `secrets.token_urlsafe(32)`, compared with `hmac.compare_digest`.           |
| Auth (vault session) | `X-GuardiaBox-Session` header pointing at an in-memory `SessionStore` entry; TTL = `Settings.auto_lock_minutes`; reaper task zero-fills on expiry. |
| Decrypt error model  | 422 + constant body for post-KDF failures; pre-KDF failures keep their distinct 400/404/409 codes.                                                 |
| Rate limit           | `slowapi` with per-endpoint buckets (table §D).                                                                                                    |
| Progress             | WebSocket `/api/v1/stream`, JSON frames, opt-in via `operation_id` query param on long ops.                                                        |
| TLS                  | None (loopback). HMAC-over-body deferred.                                                                                                          |
| Schemas              | Pydantic v2 `strict + extra=forbid + frozen`, `SecretStr` for passwords.                                                                           |
| CORS                 | Disabled.                                                                                                                                          |

## Consequences

**Positive**

- AD-2 is reduced to a 5-attempt/minute brute-force on a PBKDF2
  600 000-iteration key — a conservative ceiling that satisfies the
  threat model with zero ops burden.
- The HTTP layer cannot leak the discriminator between
  wrong-password and tampering — ADR-0015's invariant carries up
  to the WebView2 boundary unchanged.
- Auto-lock matches the existing CLI / TUI contract; users only
  re-type their password when the in-memory key is genuinely gone.
- Session zero-fill on lock and on expiry bounds the residency of
  derived keys in the sidecar's heap (with the documented Python
  caveat from THREAT_MODEL §4.5: `bytes` copies remain until GC).

**Negative**

- The 5-attempt/minute rate limit is per-process, not per-account.
  An attacker with thousands of locally-known usernames could
  iterate them within a single launch up to that ceiling. The
  brute-force economics still hold (PBKDF2 cost), but the per-user
  rate is not throttled. Tracked as a follow-up: a `failed_unlock_count`
  column already exists on `User`; wire backoff into the unlock
  router when the persistence layer can write back through the
  session boundary.
- WebSocket progress is not authenticated by the same path as HTTP
  (header transport not available) — auth via query string. The
  query string lives in process-only memory (URL bar of WebView2
  is hidden in the Tauri shell), so no observable proxy / browser
  history risk. Documented; `connect-src` CSP keeps it on loopback.
- `slowapi` is one more dependency to keep audited. Mitigated by
  pip-audit running on every PR.

**Neutral**

- The session-state map adds a `dict` to the FastAPI `app.state`.
  Memory cost: a 32-octet key per active session, plus the
  per-user `vault_key` (32 octets) — a few KiB even for power
  users with 50 vault users.
- Adding TLS later (if the sidecar ever binds beyond loopback) is
  a localized change: swap `uvicorn.Config(host="127.0.0.1")` and
  add a `ssl_keyfile`/`ssl_certfile` pair. The current decision
  does not foreclose that path.

## References

- NIST SP 800-90A Rev 1 — DRBG construction (`secrets` proxies to
  the OS CSPRNG: `getrandom(2)` / `BCryptGenRandom`).
- OWASP ASVS v4.0 §V13 — API & Web Service Verification Requirements
  (V13.1 secure transport on every endpoint, V13.2 generic
  authentication failure messages).
- CWE-208 — Observable timing discrepancy (drives
  `hmac.compare_digest`).
- CWE-307 — Improper restriction of excessive auth attempts
  (drives the `slowapi` 5/min unlock floor).
- RFC 6455 — WebSocket Protocol (transport for `/api/v1/stream`).
- ADR-0015 — anti-oracle invariant on decrypt failure (propagated
  here to the HTTP layer).
- ADR-0011 — column-level encryption fallback (the `vault_admin_key`
  is what unlocks it; this ADR governs how that key is held in the
  sidecar process).
- `docs/THREAT_MODEL.md` §4.3 — STRIDE entries for the Tauri shell ↔
  sidecar boundary.
- `docs/specs/000-tauri-sidecar/{spec,plan,tasks}.md` — implementation
  contract that this ADR backs.
