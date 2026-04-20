# DEVELOPMENT — Local setup and daily workflow

## 1. Prerequisites

| Tool                | Version           | Install                                                    |
|---------------------|-------------------|------------------------------------------------------------|
| Python              | ≥ 3.12            | https://www.python.org/downloads/                          |
| `uv`                | ≥ 0.5             | `pip install uv` *or* `curl -LsSf https://astral.sh/uv/install.sh \| sh` |
| Node.js             | ≥ 22              | https://nodejs.org/                                         |
| `pnpm`              | ≥ 10              | `npm install -g pnpm`                                       |
| Rust toolchain      | latest stable     | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh` |
| Visual Studio Build Tools (Windows) | 2022     | https://visualstudio.microsoft.com/visual-cpp-build-tools/ |
| WebView2 Runtime    | Latest            | Pre-installed on Windows 11                                 |
| SQLCipher (system)  | optional          | bundled wheel via `guardiabox[sqlcipher]`                   |

## 2. First-time setup

```bash
git clone https://github.com/sachamarlov/crypto-sidecar.git
cd crypto-sidecar

# Python side
uv sync --all-extras
uv run pre-commit install --install-hooks

# Frontend side (after Tauri scaffold lands)
pnpm --dir src/guardiabox/ui/tauri/frontend install

# Rust side (Tauri requires it)
rustup default stable
```

## 3. Daily commands cheatsheet

### Python

```bash
uv sync                                  # sync deps from uv.lock
uv add <package>                         # add a runtime dep
uv add --dev <package>                   # add a dev dep
uv lock --upgrade                        # refresh lockfile
uv run pytest                            # run all tests
uv run pytest -k encrypt                 # subset by name
uv run pytest -m 'not slow'              # subset by marker
uv run pytest --cov                      # with coverage
uv run ruff check --fix                  # lint + autofix
uv run ruff format                       # format
uv run mypy src                          # type check (until ty stable)
uv run bandit -r src                     # security static
uv run pip-audit                         # known CVEs in deps
uv run pre-commit run --all-files        # all hooks against full tree
```

### Frontend

```bash
pnpm --dir src/guardiabox/ui/tauri/frontend dev          # Vite HMR (no Tauri)
pnpm --dir src/guardiabox/ui/tauri/frontend tauri dev    # Vite + Tauri shell
pnpm --dir src/guardiabox/ui/tauri/frontend tauri build  # production .exe
pnpm --dir src/guardiabox/ui/tauri/frontend test         # Vitest
pnpm --dir src/guardiabox/ui/tauri/frontend test:e2e     # Playwright
pnpm --dir src/guardiabox/ui/tauri/frontend lint         # Biome
pnpm --dir src/guardiabox/ui/tauri/frontend lint:fix     # Biome --apply
```

### CLI usage during development

```bash
uv run guardiabox --help
uv run guardiabox encrypt /tmp/sample.txt
uv run guardiabox decrypt /tmp/sample.txt.crypt
uv run guardiabox-tui                                    # Textual UI
uv run guardiabox-sidecar                                # spawns FastAPI on 127.0.0.1:random
```

## 4. Running the full app locally

```bash
# Terminal 1 — sidecar (manual mode for debugging; Tauri auto-spawns it in prod)
uv run guardiabox-sidecar

# Terminal 2 — Tauri shell + Vite HMR
pnpm --dir src/guardiabox/ui/tauri/frontend tauri dev
```

The shell finds the sidecar's port + token by reading the line
`GUARDIABOX_SIDECAR_TOKEN=…` printed on the sidecar's stdout.

## 5. Repository layout

```
.
├── CLAUDE.md / AGENTS.md            agent rules
├── README.md                        humans entry
├── pyproject.toml                   Python project + tool config
├── uv.lock                          Python lockfile (commit it)
├── .python-version                  pinned Python version
├── .pre-commit-config.yaml          local CI gates
├── .secrets.baseline                detect-secrets baseline
├── docs/
│   ├── SPEC.md                      product spec
│   ├── ARCHITECTURE.md              technical vision
│   ├── THREAT_MODEL.md              STRIDE
│   ├── CRYPTO_DECISIONS.md          algorithms + parameters
│   ├── CONVENTIONS.md               code style
│   ├── DEVELOPMENT.md               this file
│   ├── adr/                         MADR v4 decisions log
│   ├── specs/                       Spec-Driven Dev per feature
│   └── cahier-des-charges/          official academic brief
├── src/guardiabox/
│   ├── core/                        crypto, KDF, container, secure delete
│   ├── fileio/                      safe paths, atomic writes
│   ├── security/                    password policy, keystore, audit
│   ├── persistence/                 SQLAlchemy + SQLCipher
│   ├── ui/
│   │   ├── cli/                     Typer
│   │   ├── tui/                     Textual
│   │   └── tauri/
│   │       ├── sidecar/             FastAPI server
│   │       ├── frontend/            Vite + React + shadcn (pnpm-managed)
│   │       └── src-tauri/           Tauri 2 Rust shell
│   ├── tests/                       (CDC layout placeholder; see ../tests)
│   ├── config.py                    pydantic-settings
│   └── logging.py                   structlog config
├── tests/                           authoritative test suite
│   ├── unit/
│   ├── integration/
│   ├── property/
│   └── e2e/
└── .github/                         CI/CD
```

## 6. Troubleshooting

### `uv sync` fails on `sqlcipher3-binary`

The bundled wheels are built for CPython 3.12 / Windows-x64. If on macOS,
install the upstream `sqlcipher` first (`brew install sqlcipher`) and let pip
build from source: `uv add sqlcipher3 --no-binary sqlcipher3`.

### Tauri build fails on Windows with link errors

Install the latest **MSVC v143 - VS 2022 C++ build tools** workload via the
Visual Studio Installer; Tauri's MSI bundler also needs the **WiX 3.14**
extension auto-installed by Tauri on first run.

### Pre-commit `mypy` hook is slow

`mypy` runs against the entire `src/` tree on every commit. To stage a
narrower run, `uv run mypy <changed file>` first, then commit.

### "Resource not accessible by personal access token" when GitHub Actions runs

Re-issue the token with the `actions: write`, `contents: write`, and
`metadata: read` permissions on the repo (fine-grained PAT) — see
`docs/adr/0009-github-permissions.md`.

## 7. IDE recommendations

* **VS Code** with the following extensions:
  - `ms-python.python`, `ms-python.mypy-type-checker`
  - `charliermarsh.ruff`
  - `tamasfe.even-better-toml`
  - `esbenp.prettier-vscode`
  - `biomejs.biome`
  - `bradlc.vscode-tailwindcss`
  - `Anthropic.claude-code` (if available) or your agent of choice

A workspace-level `.vscode/settings.json.example` is provided to share format/
lint settings; copy to `.vscode/settings.json` (gitignored).

## 8. Release process

1. PRs are merged with Conventional Commit titles.
2. `release-please` opens / updates a "release" PR aggregating the changelog.
3. Merging that PR creates the tag `vX.Y.Z` and triggers the release workflow:
   - Build sidecar with PyInstaller.
   - Build Tauri shell + bundle the sidecar.
   - Sign the resulting `.exe` (development cert during MVP).
   - Attach artefacts to a GitHub Release.
4. Update `CHANGELOG.md` is automatic; ADRs and specs already live in `main`.
