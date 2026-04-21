# CLAUDE.md — GuardiaBox

> Operational rules for AI coding agents working on this repository.
> Loaded into every session — keep concise. Detailed context lives in `docs/`.

## 1. Project identity

- **Product**: GuardiaBox — local secure vault (encrypt / decrypt / share files
  & messages, fully offline, zero cloud dependency).
- **Repo**: `sachamarlov/crypto-sidecar` (private). Product name and repo name
  intentionally differ.
- **Academic context**: GCS2 Bachelor 2 / DevSecOps UE 7, project #4. Final
  delivery 2026-04-29. Read `docs/cahier-des-charges/` for the official brief.

## 2. Stack at a glance

| Layer    | Tech                                                             |
| -------- | ---------------------------------------------------------------- |
| GUI      | Tauri 2 + React 19 + TypeScript + Vite + Tailwind v4 + shadcn/ui |
| Sidecar  | Python 3.12+ FastAPI + cryptography + argon2-cffi + SQLAlchemy 2 |
| Persist. | SQLite via SQLCipher (at-rest encryption)                        |
| CLI/TUI  | Typer + Textual + Rich                                           |
| Tooling  | uv, ruff, ty, pytest, hypothesis, bandit, pre-commit, pnpm       |

Rationale for every choice → `docs/adr/`. Detailed architecture →
`docs/ARCHITECTURE.md`.

## 3. Commands

```bash
# Python (sidecar, CLI, TUI)
uv sync                         # install deps from uv.lock
uv run pytest                   # run tests
uv run pytest --cov=guardiabox  # tests + coverage
uv run ruff check --fix         # lint + auto-fix
uv run ruff format              # format
uv run ty check                 # type check (fallback: uv run mypy)
uv run bandit -r src/           # security static analysis
uv run guardiabox --help        # CLI entry
uv run guardiabox-tui           # TUI entry

# Frontend (Tauri + React)
pnpm --dir src/guardiabox/ui/tauri/frontend install
pnpm --dir src/guardiabox/ui/tauri/frontend dev          # Vite HMR
pnpm --dir src/guardiabox/ui/tauri/frontend tauri dev    # Tauri dev shell
pnpm --dir src/guardiabox/ui/tauri/frontend tauri build  # production .exe
pnpm --dir src/guardiabox/ui/tauri/frontend test         # vitest
pnpm --dir src/guardiabox/ui/tauri/frontend lint         # biome

# Pre-commit
uv run pre-commit run --all-files
```

## 4. Code rules

- **Language**: code, identifiers, docstrings, commit messages → **English**.
  User-facing docs (slides, README french section, CLI help when relevant) →
  **French** (GCS2 academic compliance).
- **Conventional Commits** strictly: `feat:`, `fix:`, `docs:`, `test:`,
  `refactor:`, `chore:`, `ci:`, `build:`, `perf:`, `style:`. Scope optional but
  encouraged: `feat(security): add Argon2id KDF`.
- **DRY** — apply _Rule of Three_ before extracting an abstraction; premature
  DRY is worse than duplication.
- **SOLID, KISS (minimal abstractions), YAGNI** — see `docs/CONVENTIONS.md`.
- **Type-strict everywhere**: Python `ty`/`mypy --strict`, TypeScript `strict:
true`. No `Any` without explicit `# noqa: typing` + comment.
- **Pure functions** in `core/` whenever possible. Side effects live at the
  edges (adapters, UI, I/O).
- **Hexagonal architecture**: dependencies always point toward `core/`. UI
  layers depend on core ports, never the other way around.
- **No commented-out code, no TODOs without a tracking issue**, no dead branches.
- **Default to no comments**. Only document the _why_ when non-obvious.

## 5. Architecture invariants

- Layout: `src/guardiabox/{core,fileio,security,persistence,ui,tests}/`.
- `ui/` contains: `cli/` (Typer), `tui/` (Textual), `tauri/{frontend, sidecar.py}`.
- All cryptographic primitives live in `core/crypto/` and `core/kdf.py`. **Never
  reimplement crypto in UI layers.**
- Container format `.crypt` is versioned (`magic + version + kdf_id + ...`) —
  any change requires a new version byte and migration path. See
  `docs/CRYPTO_DECISIONS.md`.
- Database schema migrations are managed by **Alembic** only. No raw schema
  changes.

## 6. Security — non-negotiable rules

- **Never log, print, or persist** secrets, passwords, master keys, derived
  keys, or session tokens.
- **Never commit** `.env`, `*.token`, `*.pem`, `*.key`, anything under `secrets/`.
- **Always use `hmac.compare_digest`** for tag comparison (constant-time).
- **Always zero-fill** password / key buffers post-use (`bytearray.clear()`).
- **Always validate path inputs** via `Path.resolve()` + ancestor check (no
  string concat, no symlink follow outside vault root).
- **Never weaken KDF parameters below**: PBKDF2-SHA256 600 000 iter, Argon2id
  m=64 MiB t=3 p=1.
- **Sidecar binds to 127.0.0.1 only**, never 0.0.0.0. Auth via random session
  token generated on startup.
- Read `docs/THREAT_MODEL.md` before touching `security/`, `core/crypto/`, or
  the Tauri↔sidecar IPC.

## 7. Testing rules

- **Unit tests** for all `core/` and `security/` modules: 100% line coverage
  target.
- **Property-based tests** (hypothesis) for crypto roundtrip:
  `decrypt(encrypt(x, p), p) == x` for arbitrary `x`, `p`.
- **Integration tests** for sidecar HTTP API and DB layer.
- **E2E tests** (Playwright) for critical Tauri flows (encrypt, decrypt, share).
- A failing test = a blocked merge. **Never** mark a test xfail without an ADR.
- Test data lives in `tests/fixtures/`, **never** real user data.

## 8. Git workflow

- **Branch from `main`**: `feat/`, `fix/`, `docs/`, `chore/`, `refactor/`...
- **One PR per logical change**. Squash-merge into `main` with conventional
  title.
- **Commit message format** mandated by `commitlint` (Conventional Commits).
- All commits include `Co-Authored-By: Claude Opus 4.7 (1M context)
<noreply@anthropic.com>` when the agent contributed.
- `main` is protected: PR + green CI required.
- **Never** `--force` push to `main`. Never amend a pushed commit. Never skip
  hooks (`--no-verify`).

## 9. When to ask the user vs act autonomously

- **Act autonomously**: any code change covered by an existing spec, ADR, or
  this CLAUDE.md. Refactors that preserve behavior. Test additions. Doc updates.
  Routine deps updates passing CI.
- **Ask first**: any new ADR-worthy decision (new dependency, architectural
  shift, crypto parameter change, breaking API change). Any destructive Git op.
  Any change to security defaults. Anything outside the agreed scope.

## 9bis. CI red is acceptable. Lowering the gate is not.

- **CI may be red on stub code.** Until a feature spec lands, the strict
  ruff / mypy / coverage / bandit gates can legitimately fail. That is
  signal, not noise — it lists the work to do.
- **Never lower a quality gate to make CI green.** Forbidden moves include:
  - Dropping `--cov-fail-under` below the agreed floor.
  - Adding rules to ruff `ignore` to silence warnings on real bugs.
  - Adding `continue-on-error: true` to a security-relevant job.
  - Removing a step from the workflow because it currently fails.
  - Replacing a granular permission set with `<plugin>:default` bundles.
  - Demoting a security-relevant dependency to optional to bypass an
    install error.
- If a gate is genuinely too strict for the bootstrap phase (e.g.
  `D102` on stubs), document the relaxation in CONVENTIONS.md and add
  a TODO with a target date to re-tighten it.
- **Always run the local toolchain before push**:
  `uv run pre-commit run --all-files && uv run pytest && uv run mypy src`.
- **Always document a known regression with an ADR of supersession**
  if it changes a previously-accepted invariant. No silent regressions.

## 10. Pointers — where to read more

| Topic                            | Read                             |
| -------------------------------- | -------------------------------- |
| Product vision & user features   | `docs/SPEC.md`                   |
| Technical architecture & flows   | `docs/ARCHITECTURE.md`           |
| Threat model (STRIDE)            | `docs/THREAT_MODEL.md`           |
| Crypto choices & parameters      | `docs/CRYPTO_DECISIONS.md`       |
| Code conventions (SOLID/DRY/...) | `docs/CONVENTIONS.md`            |
| Local dev setup                  | `docs/DEVELOPMENT.md`            |
| Architectural decisions log      | `docs/adr/` (MADR v4)            |
| Per-feature specs                | `docs/specs/<NNN-feature>/`      |
| Original CDC (academic brief)    | `docs/cahier-des-charges/`       |
| Persistent agent memory          | `~/.claude/projects/.../memory/` |
| Contribution rules               | `CONTRIBUTING.md`                |
| Vulnerability reporting          | `SECURITY.md`                    |

## 11. Anti-patterns to refuse

- ❌ Adding a feature not specified in `docs/specs/`.
- ❌ Disabling a security rule "for testing" (use a fixture instead).
- ❌ Committing without running `pre-commit`.
- ❌ Importing crypto code in `ui/` layers directly (always go through `core/`).
- ❌ Adding a dependency without a justifying ADR.
- ❌ Using `print()` for logs (use `structlog` / `loguru`).
- ❌ Mocking the database in integration tests (use a real SQLite fixture).
- ❌ Lowering a quality gate to "make CI green" (cf. §9bis).
- ❌ Demoting a security-relevant dependency to optional to silence an
  install error (cf. ADR-0011 for the principle).
- ❌ Replacing granular Tauri capabilities with `<plugin>:default`
  bundles to "make build pass".
- ❌ Adding `continue-on-error: true` to a security workflow.

---

_This file follows Anthropic's CLAUDE.md best practices (≤200 lines target)._
_Last reviewed: 2026-04-20._
