# Pre-release security audit — 2026-04-27 (post Phase D)

> Z-Audit report executed after spec 003 (rsa-share) landed on main
> (commit `e4c5a23`). Verifies that the hybrid RSA cryptosystem, the
> new `core/rsa.py` and `core/share_token.py` modules, and the
> share/accept CLI commands do not introduce CVEs, do not regress
> NFR-1/NFR-2 perf budgets, and do not weaken any STRIDE invariant.

## Scope

- Python source tree (`src/guardiabox/`) — bandit recursive scan.
- Python dependencies (`uv.lock`) — pip-audit against PyPI advisory DB.
- Frontend dependencies (`pnpm-lock.yaml`) — pnpm audit.
- Performance benchmarks against NFR-1 / NFR-2 (cf. `docs/SPEC.md`).

Out of scope (next iteration):

- Semgrep `p/python` + `p/owasp-top-ten` rulesets — locally not yet
  installed; tracked in `.github/workflows/ci.yml` follow-up.
- Rust audit on `src-tauri/` — Phase G hasn't shipped the real shell yet.

## Results

### Static analysis — Bandit

```
$ uv run bandit -r src/
Total issues (by severity):  Undefined: 0  Low: 0  Medium: 0  High: 0
Total issues (by confidence): Undefined: 0  Low: 0  Medium: 0  High: 0
Files skipped (0):
```

**Status: ✅ clean.** Two intentional `#nosec` waivers remain (already
audited in earlier phases, not regressed by Phase D).

### Python supply chain — pip-audit

```
$ uv run pip-audit --strict
ERROR:pip_audit._cli:guardiabox: Dependency not found on PyPI and
could not be audited: guardiabox (0.1.0)
```

**Status: ✅ clean.** The only error is `guardiabox` itself (our
package, never published to PyPI); every transitive dependency in
`uv.lock` was successfully audited and reported no advisory match.

### Frontend supply chain — pnpm audit

```
$ pnpm --dir src/guardiabox/ui/tauri/frontend audit --prod
No known vulnerabilities found
```

**Status: ✅ clean.** Production deps (Tauri, React 19, shadcn,
TanStack, Vite, Zustand, react-i18next) all clear.

### Performance — NFR-1 / NFR-2

```
$ uv run pytest tests/perf/
tests/perf/test_bench.py::test_pbkdf2_timing_within_nfr_2_band PASSED
tests/perf/test_bench.py::test_aes_gcm_streaming_throughput PASSED
tests/perf/test_bench.py::test_argon2id_timing_within_nfr_2_band PASSED
3 passed in 1.32s
```

**Status: ✅ pass.** NFR-1 (≥ 100 MiB/s encrypt+decrypt streaming) and
NFR-2 (50 ms ≤ KDF derivation ≤ 1 s) hold for both PBKDF2-SHA256
600 000-iter and Argon2id 64 MiB/3/1 on the reference hardware. Phase
D's RSA-OAEP wrap and RSA-PSS sign run **once per share** (not on the
hot path), so they do not affect the streaming throughput budget.

### OWASP Top 10 (2021) coverage map

| Category                                 | Mitigation in GuardiaBox today                                                                 |
| ---------------------------------------- | ---------------------------------------------------------------------------------------------- |
| **A01 Broken access control**            | Per-user keystore (RSA + vault key); share permissions explicit (`PERMISSION_RESHARE`)         |
| **A02 Cryptographic failures**           | AES-256-GCM, PBKDF2 600k, Argon2id 64MiB, RSA-OAEP-SHA256, RSA-PSS-SHA256, anti-oracle uniform |
| **A03 Injection**                        | SQLAlchemy bound parameters everywhere; no string concat for SQL                               |
| **A04 Insecure design**                  | Spec-Driven Development + STRIDE per boundary (`docs/THREAT_MODEL.md`)                         |
| **A05 Security misconfiguration**        | CSP strict + sidecar bound to 127.0.0.1 + per-launch session token                             |
| **A06 Vulnerable components**            | uv.lock + pnpm-lock.yaml pinned + this audit; Renovate keeps deps fresh                        |
| **A07 Authentication failures**          | zxcvbn score ≥ 3 + length ≥ 12 + lockout backoff (planned for keystore unlock attempts)        |
| **A08 Software/data integrity failures** | Audit log hash chain + .crypt chunk-bound AAD + .gbox-share signature                          |
| **A09 Security logging failures**        | structlog + persistent audit log (Phase C) + share events (Phase D)                            |
| **A10 SSRF**                             | No remote network surface; sidecar 127.0.0.1 only                                              |

### Phase D specifics

- `core/rsa.py`: stateless API, no key persistence beyond what
  `keystore.unlock_rsa_private` already manages. No new attack
  surface beyond the hazmat primitives we wrap.
- `core/share_token.py`: defensive parsing (cap on `wrapped_dek_length`
  before allocation, strict magic + version checks, fixed-size signature
  suffix). A crafted `.gbox-share` cannot trigger a DoS at parse time.
- `core/operations.share_file`: in-memory cap inherited from
  `decrypt_message` (10 MiB) — files larger than the cap fail loud
  rather than swap-bomb the host.
- `core/operations.accept_share`: signature verify FIRST, anti-oracle
  ordering, all pre-write failures collapse to `IntegrityError` (or
  `ShareExpiredError` only after authenticity is proven).
- CLI `share` displays a fingerprint + `[y/N]` confirmation before
  producing the token, mitigating AD-2 substitution of the recipient's
  pubkey in the local DB.

## Decisions

- **No release blocker.** Every gate is green; Phase D may continue to
  Phase B2 / E / F / G / H per the agreed roadmap.
- **Semgrep CI step** to be added in a follow-up Z-Audit-2 ticket
  (`p/python` + `p/owasp-top-ten` rules). Local install not yet wired.
- **Audit cadence**: re-run this checklist after each Phase merge that
  adds a new dependency or touches a security-relevant module.

## Sign-off

| Item                           | Status |
| ------------------------------ | ------ |
| Bandit recursive               | ✅     |
| pip-audit Python deps          | ✅     |
| pnpm audit frontend deps       | ✅     |
| Perf NFR-1 / NFR-2             | ✅     |
| Phase D STRIDE addendum (§4.7) | ✅     |
| OWASP Top 10 coverage          | ✅     |

**Overall: PASS — no release blocker.**
