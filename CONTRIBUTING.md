# Contributing to GuardiaBox

Thanks for your interest. This file documents the workflow expected from any
human or AI contributor.

## Prerequisites

- Python ≥ 3.12, [`uv`](https://docs.astral.sh/uv/) installed
- Node.js ≥ 22, [`pnpm`](https://pnpm.io/) ≥ 10
- Rust toolchain via [`rustup`](https://rustup.rs/) (for Tauri)
- Git ≥ 2.40 with `gh` CLI authenticated

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md) for the full local setup.

## Workflow

1. **Sync `main`**: `git checkout main && git pull --ff-only`.
2. **Create a branch** from `main`:
   ```
   feat/<short-kebab-description>
   fix/<short-kebab-description>
   docs/<short-kebab-description>
   refactor/<short-kebab-description>
   chore/<short-kebab-description>
   ```
3. **If the change is architectural**, write the corresponding ADR first under
   `docs/adr/NNNN-<title>.md` (MADR v4 template).
4. **If the change is a feature**, write the spec first under
   `docs/specs/NNN-<feature>/spec.md` (Spec-Driven Development).
5. **Code, test, document** (in that order if practical).
6. **Pre-commit must pass** locally:
   ```
   uv run pre-commit run --all-files
   ```
7. **Open a PR** to `main` with a Conventional Commits-style title:
   ```
   feat(security): add Argon2id KDF as opt-in alternative to PBKDF2
   ```
8. **CI must be green** (lint, type, tests, security scans).
9. **Squash-merge** into `main` once approved.

## Conventional Commits

Format: `<type>(<scope>): <subject>`.

| Type       | When to use                                |
| ---------- | ------------------------------------------ |
| `feat`     | New feature                                |
| `fix`      | Bug fix                                    |
| `docs`     | Documentation only                         |
| `style`    | Formatting, whitespace (no code change)    |
| `refactor` | Code restructuring without behavior change |
| `perf`     | Performance improvement                    |
| `test`     | Test additions or fixes only               |
| `build`    | Build system, dependencies                 |
| `ci`       | CI/CD configuration                        |
| `chore`    | Tooling, scaffolding, miscellaneous        |

Examples:

- `feat(ui-tauri): add command palette with cmd+K`
- `fix(crypto): zero-fill key buffer on Decryption error`
- `docs(adr): record decision to use SQLCipher for at-rest encryption`
- `refactor(persistence): extract VaultRepository protocol`

## Code style

- Python: `ruff check` + `ruff format` + `mypy --strict` must pass. We track
  Astral's `ty` type-checker for adoption once it is stable on PyPI; until
  then `mypy` is authoritative. See [`docs/CONVENTIONS.md`](docs/CONVENTIONS.md).
- TypeScript: `biome check` must pass. Strict mode is mandatory.
- Rust (Tauri): `cargo fmt` + `cargo clippy --all-targets -- -D warnings`.

The `commit-msg` Conventional-Commits gate is enforced by the
`compilerla/conventional-pre-commit` hook configured in
[`.pre-commit-config.yaml`](.pre-commit-config.yaml). No JavaScript-side
`commitlint` / `husky` is needed — pre-commit handles the entire chain.

## Tests

- Add tests for any new public API. Coverage target: ≥ 90% on `core/` and
  `security/`.
- Use property-based tests (hypothesis) for crypto roundtrips.
- Integration tests must hit a real SQLite (no mocking the DB).
- E2E tests (Playwright) for critical Tauri flows.

## AI agent contributions

When an AI agent (Claude Code, Cursor, Copilot, etc.) authors a commit, the
commit message must include the appropriate `Co-Authored-By:` trailer:

```
Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
```

The same applies for any other agent: identity must be transparent.

## Security disclosure

For any vulnerability, **do not open a public issue**. See
[`SECURITY.md`](SECURITY.md).
