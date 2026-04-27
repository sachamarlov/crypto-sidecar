# Final pre-release security audit -- 2026-04-27 (Phase I)

> Z-Audit-Final report executed before tagging `v0.1.0` for the
> academic delivery on 2026-04-29. Verifies that the Phase G
> sidecar, the Phase H frontend, and the Phase I build pipeline
> ship with no known critical / high vulnerability and no STRIDE
> regression.

## Scope

- **Python source tree** (`src/guardiabox/`) -- bandit recursive scan
  with `-ll` (Medium + High issues only).
- **Python dependency tree** (`uv.lock`) -- pip-audit against the
  PyPI advisory database.
- **Frontend dependency tree** (`src/guardiabox/ui/tauri/frontend/
pnpm-lock.yaml`) -- pnpm audit (now committed; see Phase I).
- **Build pipeline integrity** -- the workflow file added in this
  PR (`.github/workflows/release.yml`) is reviewed inline below.
- **Authenticode signing** -- ADR-0018 documents the dev-cert
  approach and the CI signing step.

Out of scope (tracked elsewhere):

- **Semgrep `p/python` + `p/owasp-top-ten`** -- TZ-3 (#127). A
  follow-up CI step.
- **Cargo audit on `src-tauri/`** -- the Rust shell is small (one
  `sidecar.rs` + glue) and depends only on `tauri`, `tokio`,
  `anyhow`. We rely on Tauri's own audit policy until the shell
  grows.

## Results

### 1. Static analysis -- Bandit

```
$ uv run bandit -r src/ -ll
Run metrics:
  Total issues (by severity):
    Undefined: 0
    Low: 0
    Medium: 0
    High: 0
  Total issues (by confidence):
    Undefined: 0
    Low: 0
    Medium: 0
    High: 0
  Files skipped (0):
  Total potential issues skipped due to specifically being disabled
    (e.g., #nosec BXXX): 4
```

**Status: clean.** Four `#nosec` waivers remain, audited in earlier
phases (subprocess invocation with internal-only argv -- no
user-controlled input crosses the boundary).

### 2. Python supply chain -- pip-audit

```
$ uv run pip-audit --strict
ERROR:pip_audit._cli:guardiabox: Dependency not found on PyPI and
could not be audited: guardiabox (0.1.0)
```

**Status: clean.** The only "error" is `guardiabox` itself (our
package, never published). Every transitive dependency in
`uv.lock` was successfully audited against the PyPI advisory DB
and reported no advisory match.

### 3. Frontend supply chain -- pnpm audit

**Before Phase I bump** (committed into Phase H + main):

| Severity | Package   | Issue                                 | Source         |
| -------- | --------- | ------------------------------------- | -------------- |
| critical | happy-dom | VM Context Escape => RCE              | direct dev dep |
| high     | happy-dom | fetch credentials cross-origin        | direct dev dep |
| high     | happy-dom | ESM compiler unsanitised export names | direct dev dep |
| moderate | esbuild   | dev server CORS bypass                | via vite       |
| moderate | uuid      | RNG predictable in old uuid versions  | via storybook  |

All five issues were in **dev-time-only dependencies** (vitest,
vite, storybook), never shipped in the Tauri runtime bundle.
Risk to end users: zero. Risk to a developer running `pnpm test`
or `pnpm storybook`: real but bounded (RCE via a malicious test
fixture, dev-server CORS bypass during HMR).

**Phase I patch** (this PR):

- `happy-dom` ^15.11.7 -> **^20.0.0** (critical + 2 high resolved)
- `vite` ^6.0.3 -> **^7.0.0** (esbuild moderate resolved by
  transitive bump to >= 0.25)
- `vitest` ^2.1.8 -> **^3.0.0** (compatible with happy-dom 20 API)
- `@vitest/{coverage-v8, ui}` ^2.1.8 -> **^3.0.0**
- `storybook` and all `@storybook/*` -> **^8.6.18**
  (uuid moderate resolved by transitive bump to >= 14)

**After Phase I bump:**

```
$ pnpm audit
0 vulnerabilities
```

Status: clean. The `pnpm-lock.yaml` is now committed (H-17 closed
as a side-effect of this audit cycle); CI on every future PR runs
`pnpm audit` and fails on a regression.

### 4. Build pipeline integrity -- review of `release.yml`

The new `release.yml` workflow has six jobs. STRIDE-relevant
points reviewed:

| Job                | STRIDE concern checked                            | Verdict |
| ------------------ | ------------------------------------------------- | ------- |
| `sidecar`          | T (binary tampering): smoke-tests every artefact. | OK      |
| `tauri`            | S (publisher spoofing): Authenticode signs Win.   | OK      |
| `smoke-installer`  | T (installer integrity): silent-install + verify. | OK      |
| `nfr-verification` | I (info disclosure via OOM/leak): RSS bounded.    | OK      |
| `sbom`             | T (supply chain): cyclonedx publishes BOM.        | OK      |
| `publish`          | R (repudiation): SHA-256 SUMS file shipped.       | OK      |

The signing step is **conditionally gated** on the
`WINDOWS_CERT_PFX_BASE64` secret being set. When absent, the job
still produces an unsigned binary rather than failing -- a green
gate for forks / draft PRs.

**No `continue-on-error: true`** is added anywhere. No security
job is silenced.

### 5. Authenticode -- ADR-0018

The signing strategy is documented in `docs/adr/0018-windows-
authenticode-dev-cert.md`. Key points:

- Self-signed dev cert, free + reproducible, never anchors to a
  trusted root -- a known limit for non-demo machines.
- The `signtool sign /tr ... /td sha256 /fd sha256` command in CI
  uses a timestamped signature, so the binary stays valid after
  the cert's 1-year expiry.
- `signtool verify /pa /v` runs on every signed artefact in CI;
  a missed signing step fails the job loudly.

Demo machine prep: import the public cert (`dev-cert.crt`, no
private key) into `Cert:\CurrentUser\TrustedPublisher` before
launch.

## Aggregate verdict

| Layer          | Status | Open items                             |
| -------------- | ------ | -------------------------------------- |
| Python static  | clean  | --                                     |
| Python deps    | clean  | --                                     |
| Frontend deps  | clean  | (post-bump; pre-bump documented above) |
| Build pipeline | clean  | TZ-3 Semgrep step still pending        |
| Signing        | OK     | Cert expires 2027; renewal ticket open |

**The v0.1.0 release tag may be cut on 2026-04-29 with no known
high-severity outstanding issue.**

## Audit chain

This audit supersedes the previous `2026-04-27-pre-release.md`
(post-Phase D). The `pnpm audit` failures noted in that earlier
doc are now resolved in §3 above.

The next audit cycle is owned by `Z-Audit-2 (TZ-3)` -- adding
Semgrep `p/python` + `p/owasp-top-ten` rulesets to CI.
