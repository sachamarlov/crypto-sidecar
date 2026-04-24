# THREAT MODEL — STRIDE analysis

> Living document — update on every architectural change. Methodology: STRIDE
> per data-flow boundary, mitigations linked to ADRs.

## 1. Assets to protect (in priority order)

| #   | Asset                         | Why it matters                               |
| --- | ----------------------------- | -------------------------------------------- |
| A1  | User's master password        | Root secret; compromise unlocks everything   |
| A2  | Per-user vault key            | Decrypts the SQLCipher database content      |
| A3  | Per-file data-encryption keys | Decrypts individual `.crypt` files           |
| A4  | RSA private key (per user)    | Allows unwrapping shared keys                |
| A5  | Plaintext file content        | The actual data the user is protecting       |
| A6  | Audit log integrity           | Forensic value depends on tamper-evidence    |
| A7  | Session token (sidecar)       | Authorises requests during an active session |

## 2. Trust boundaries

1. **OS user account ↔ rest of the world** — assumed trusted (the project
   does not protect against an OS-level attacker with admin rights).
2. **GuardiaBox process ↔ other user-space processes** — partially trusted;
   we mitigate trivial inspection (no plaintext on disk, secrets zero-filled),
   but we don't fight a kernel-mode attacker.
3. **Tauri shell ↔ Python sidecar** — communication over loopback only,
   authenticated by a per-launch session token.
4. **WebView2 (renderer) ↔ Tauri shell** — strict CSP, no `nodeIntegration`
   equivalent, sandboxed Tauri commands.
5. **GuardiaBox ↔ remote network** — there is no remote network. The sidecar
   binds 127.0.0.1 only.

## 3. Adversaries we model

| Code | Adversary                                    | Capabilities                            |
| ---- | -------------------------------------------- | --------------------------------------- |
| AD-1 | **Remote attacker over network**             | None — there is no public surface       |
| AD-2 | **Local non-privileged process**             | Read filesystem, observe processes      |
| AD-3 | **Local user with the laptop in hand**       | Boot from USB, copy disk, brute-force   |
| AD-4 | **Curious developer / packager**             | Read the source, the binaries, the docs |
| AD-5 | **Malicious recipient of a shared file**     | Holds a legitimate `.gbox-share` file   |
| AD-6 | **Physical attacker (cold-boot, evil maid)** | Out of scope (mitigated at OS level)    |

## 4. STRIDE analysis per boundary

### 4.1 Boundary: User keyboard → CLI / GUI input field

| Threat                       | Risk                              | Mitigation                                                                                     |
| ---------------------------- | --------------------------------- | ---------------------------------------------------------------------------------------------- |
| **S** Spoofing               | Phishing UI mimicking GuardiaBox  | Frameless transparent window with custom title chrome (visual identity)                        |
| **T** Tampering              | Keylogger captures password       | Out of scope (OS responsibility); recommend Windows Hello in roadmap                           |
| **R** Repudiation            | User denies having encrypted file | _Planned (spec 000-multi-user)_: persistent audit log with timestamp + actor. Not yet shipped. |
| **I** Information disclosure | Password echoed                   | All password prompts use no-echo input. Key buffers zero-filled **best-effort** (see §4.5).    |
| **D** Denial of service      | Locked out by typo bursts         | Exponential backoff up to 15 min, never permanent lockout (BIP-39)                             |
| **E** Elevation              | n/a                               | n/a                                                                                            |

### 4.2 Boundary: WebView2 (renderer) ↔ Tauri Rust shell

| Threat | Mitigation                                                                     |
| ------ | ------------------------------------------------------------------------------ |
| **S**  | Tauri commands are explicitly allowlisted; no auto-exposure of native APIs.    |
| **T**  | Strict CSP `default-src 'self'; connect-src http://127.0.0.1:*`.               |
| **I**  | Renderer never touches the database; all sensitive ops go through the sidecar. |
| **E**  | No `unsafe_eval`; no remote script loading; bundled assets only.               |

### 4.3 Boundary: Tauri shell ↔ Python sidecar

| Threat | Mitigation                                                                                                                                                                               |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **S**  | Session token (32 random bytes) generated by sidecar at launch, read from sidecar's stdout, attached to every shell→sidecar request.                                                     |
| **T**  | TLS unnecessary on loopback (kernel-only path). HMAC over each request body could be added if needed.                                                                                    |
| **R**  | _Planned (spec 000-multi-user)_: every sidecar request appended to the persistent audit log. Current builds emit structured events via `structlog` that do **not** survive process exit. |
| **I**  | Sidecar binds 127.0.0.1 only; OS firewall blocks external access.                                                                                                                        |
| **D**  | Sidecar enforces request rate limit (`slowapi`).                                                                                                                                         |
| **E**  | Sidecar runs as the same user; no privilege boundary to cross.                                                                                                                           |

### 4.4 Boundary: Sidecar ↔ disk (SQLCipher DB + .crypt files)

| Threat | Mitigation                                                                                                                                                                                     |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **S**  | n/a (single-process owner).                                                                                                                                                                    |
| **T**  | `.crypt` integrity = AES-GCM tag; DB integrity = audit log hash chain + SQLCipher MAC.                                                                                                         |
| **R**  | _Planned (spec 000-multi-user)_: audit log entries reference the prior entry's hash (hash chain). Not yet shipped.                                                                             |
| **I**  | `.crypt` content authenticated (AES-GCM tag). DB encryption at rest planned with spec 000-multi-user (SQLCipher or column-level AES-GCM per ADR-0011).                                         |
| **D**  | Secure delete uses DoD 5220.22-M overwrite today (spec 004 Phase B1); cryptographic erase key destruction planned for Phase B2 (needs keystore). SSD wear-levelling disclosed via CLI warning. |
| **E**  | n/a                                                                                                                                                                                            |

### 4.5 Boundary: Memory of a running sidecar

| Threat | Mitigation                                                                                                    |
| ------ | ------------------------------------------------------------------------------------------------------------- |
| **I**  | **Best-effort** zero-fill of derived key buffers. See note below for Python limits.                           |
| **D**  | Auto-lock after `auto_lock_minutes` of inactivity zeroises in-memory keys (planned with spec 000-multi-user). |

**Zero-fill in Python — honest limits.** The code zero-fills the
`bytearray` buffer that holds the derived key in a `try/finally` block.
However, Python's `bytes` objects are immutable; the `bytes(key_buf)`
copy passed into `cryptography.AESGCM(key)` and the `bytes` returned by
`kdf.derive()` **cannot** be zero-filled at the Python level. They
remain in the CPython heap until the garbage collector reclaims them,
and the underlying Rust `cryptography` context stores its own copy
that lives until `AESGCM.__del__`. Concretely:

- A **local non-privileged process** (AD-2) on the same machine
  cannot read another user's process memory without kernel-level
  escalation — the residual copies pose a limited risk.
- A **cold-boot / DMA attacker** (AD-6, out of scope) or someone
  running a debugger under the same user (`ptrace` on Linux,
  `ReadProcessMemory` on Windows) can recover these copies.

Future work (post-MVP): move key material to a `ctypes`-backed
mlocked buffer with explicit `memset` on cleanup, or call
`cryptography.exceptions.InternalError`-grade primitives that wipe
their own context. Until then, the mitigation is documented as
partial rather than claimed as complete.

### 4.6 Boundary: secure deletion of plaintext files

Spec 004 Phase B1 ships the overwrite path. Phase B2 adds crypto-erase
once the keystore lands (spec 000-multi-user).

| Threat | Mitigation                                                                                                                                                                                                                                                                                           |
| ------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **I**  | DoD 5220.22-M three-pass overwrite (zero / one / random, `fsync` after each pass) before `unlink`. On SSDs wear-levelling may remap blocks — NIST SP 800-88r2 §5.2. The CLI **detects SSD** via `fileio.platform.is_ssd` and warns the user before proceeding, recommending crypto-erase (Phase B2). |
| **T**  | `_overwrite_dod` rejects directories and symlinks ; the atomic `r+b` write keeps the inode stable throughout the pass so neighbouring files are untouched.                                                                                                                                           |
| **D**  | A kill mid-way leaves the file in a zero/one/random state — irretrievable for the original content, at worst a partially overwritten copy of the pattern, never a partial plaintext.                                                                                                                 |

## 5. Residual risks (acknowledged, not mitigated by the app)

- **R-1** — Compromise of the host OS or the user account. _Mitigation:_ keep
  the OS patched, enable BitLocker / FileVault / dm-crypt.
- **R-2** — Cold-boot or DMA attacks on a powered-on machine. _Mitigation:_
  full-disk encryption + secure boot + lock the screen.
- **R-3** — Side-channel attacks (timing, cache) by a co-tenant on the same
  CPU. _Mitigation:_ `hmac.compare_digest`; `cryptography` lib uses constant-
  time AES-NI; Argon2 is memory-hard which limits cache amplification.
- **R-4** — Supply-chain compromise of a Python or npm dependency.
  _Mitigation:_ `uv.lock` + `pnpm-lock.yaml` pinned; CI runs `pip-audit` +
  `npm audit` on every PR; Renovate bot keeps deps fresh.

## 6. Database at-rest exposure (Win/Mac without SQLCipher)

ADR-0011 documents the cross-platform constraint that prevents SQLCipher
from being a single-build solution. Without SQLCipher, the metadata
database (filenames, audit log, RSA public keys, KDF parameters) would
be readable by an attacker who copies the file from disk.

| State                                       | Mitigation                                                                                                                                                                                                                |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Linux (default)                             | SQLCipher (AES-256-CBC + HMAC-SHA-512 per page) auto-installed via `sqlcipher3-binary`. Full DB encrypted.                                                                                                                |
| Win/Mac (default)                           | **Column-level AES-GCM** at the repository boundary (see ADR-0011 + spec 002). Encrypts every sensitive column with a key derived from the vault administrator password; deterministic HMAC indices for equality lookups. |
| Win/Mac (opt-in `--extra sqlcipher-source`) | SQLCipher built from source. Equivalent to Linux baseline.                                                                                                                                                                |

**Recommended user mitigation regardless of platform**: enable OS-level
full-disk encryption (BitLocker / FileVault / dm-crypt). This protects
against offline attacks (stolen laptop, copied backup) where neither
SQLCipher nor column-level encryption can defend on their own (e.g.,
because the attacker also captures the running process memory).

## 7. Cross-references

- Cryptographic parameter justifications: [`CRYPTO_DECISIONS.md`](CRYPTO_DECISIONS.md)
- Architectural choices: [`docs/adr/`](adr/)
- Security non-negotiables enforced by code review: [`../CLAUDE.md`](../CLAUDE.md)
- Vulnerability reporting policy: [`../SECURITY.md`](../SECURITY.md)
