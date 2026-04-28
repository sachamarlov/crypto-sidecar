# DEVELOPMENT — Local setup and daily workflow

## 1. Prerequisites

| Tool                                | Version       | Install                                                                                                                      |
| ----------------------------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------- |
| Python                              | ≥ 3.12        | https://www.python.org/downloads/                                                                                            |
| `uv`                                | ≥ 0.5         | `pip install uv` _or_ `curl -LsSf https://astral.sh/uv/install.sh \| sh`                                                     |
| Node.js                             | ≥ 22          | https://nodejs.org/                                                                                                          |
| `pnpm`                              | ≥ 10          | `npm install -g pnpm`                                                                                                        |
| Rust toolchain                      | latest stable | `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \| sh`                                                            |
| Visual Studio Build Tools (Windows) | 2022          | https://visualstudio.microsoft.com/visual-cpp-build-tools/                                                                   |
| WebView2 Runtime                    | Latest        | Pre-installed on Windows 11                                                                                                  |
| SQLCipher (Linux)                   | auto          | Pre-built wheel `sqlcipher3-binary` installed by `uv sync`                                                                   |
| SQLCipher (Win/Mac)                 | optional      | System library (`vcpkg install sqlcipher` / `brew install sqlcipher`) then `uv sync --extra sqlcipher-source` — see ADR-0011 |

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

`sqlcipher3-binary` only ships a Linux x86_64 wheel on PyPI. On Windows
or macOS:

1. Install the system library first
   - Windows: `vcpkg install sqlcipher`
   - macOS: `brew install sqlcipher`
2. Then install the source binding via the dedicated extra:
   ```bash
   uv sync --extra sqlcipher-source
   ```

If you skip these steps, GuardiaBox still runs — the persistence layer
falls back to **column-level AES-GCM encryption** of sensitive columns
(filenames, audit metadata) so the metadata-protection floor is preserved
on every platform. See [ADR-0011](adr/0011-defer-cross-platform-database-encryption.md)
for the full strategy.

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

- **VS Code** with the following extensions:
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

## 9. Build & test the release artefact locally (Windows)

**Verified end-to-end on 2026-04-28** -- this section reflects what
actually works, including the gotchas observed on a clean Windows 11
machine.

### 9.1 Toolchain prerequisites

Three install steps with documented gotchas:

1. **Rust MSVC toolchain.** The official `https://win.rustup.rs/x86_64`
   download is sometimes blocked by endpoint protection (TLS reset).
   The fallback that worked: `winget install Rustlang.Rustup
--accept-source-agreements --accept-package-agreements`.

2. **Default toolchain ships as `gnu` (MinGW)**, but Tauri 2 on Windows
   needs MSVC. After install:

   ```powershell
   rustup toolchain install stable-x86_64-pc-windows-msvc
   rustup default stable-x86_64-pc-windows-msvc
   ```

3. **Visual Studio 2022 Build Tools** (or VS 2022 Community) must be
   present at `C:\Program Files\Microsoft Visual Studio\2022\`. Tauri
   needs `link.exe`, `cl.exe`, the Windows SDK, and `vcvars64.bat`.

### 9.2 PATH ordering (critical Windows-only gotcha)

In Git for Windows' bash MINGW shell, `/usr/bin/link.exe` is the GNU
hard-linker, **not** the MSVC linker. When Cargo tries to link, it
finds the wrong `link` first and errors with `extra operand` /
`dlltool.exe: program not found`.

The fix is to source MSVC's `vcvars64.bat` **after** putting cargo's
bin in PATH, so MSVC's `link.exe` and SDK paths are prepended:

```cmd
set PATH=%USERPROFILE%\.cargo\bin;%PATH%
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
```

### 9.3 Build the sidecar (Python + PyInstaller)

```bash
uv run python scripts/build_sidecar.py --release --smoke-test
```

Produces `src/guardiabox/ui/tauri/src-tauri/binaries/guardiabox-sidecar-x86_64-pc-windows-msvc.exe`.
Smoke test asserts handshake + `/healthz` + clean SIGTERM.

### 9.4 Build the frontend bundle (Vite)

```bash
pnpm --dir src/guardiabox/ui/tauri/frontend build
```

Produces `frontend/dist/`. Required before `tauri build` because
`tauri.conf.json > beforeBuildCommand` is currently disabled (pnpm
path-resolution bug under src-tauri cwd).

### 9.5 Build the Tauri bundle

From a Developer Command Prompt (or any cmd shell where MSVC is in
PATH per 9.2):

```cmd
cd C:\path\to\repo\src\guardiabox\ui\tauri\src-tauri
node ..\frontend\node_modules\@tauri-apps\cli\tauri.js build
```

Tauri:

1. Compiles ~600 Rust deps (one-time ~6-10 min, then cached in
   `target/`).
2. Auto-downloads NSIS 3.11 + WiX 3.14 to produce installers.
3. Embeds the sidecar from `binaries/` into the bundle via
   `bundle.externalBin`.

Outputs:

- `target/release/guardiabox.exe` -- the Tauri shell (~6 MiB).
- `target/release/guardiabox-sidecar.exe` -- the PyInstaller sidecar
  copied next to the shell (~42 MiB).
- `target/release/bundle/nsis/GuardiaBox_<version>_x64-setup.exe` --
  NSIS installer (~46 MiB compressed).
- `target/release/bundle/msi/GuardiaBox_<version>_x64_en-US.msi` and
  `_fr-FR.msi` -- WiX MSI installers (~46 MiB each).

### 9.6 Run the bundled app

```cmd
target\release\bundle\nsis\GuardiaBox_0.1.0_x64-setup.exe /S
"%PROGRAMFILES%\GuardiaBox\GuardiaBox.exe"
```

### 9.7 NFR measurements on the produced artefact

```bash
uv run python scripts/verify_nfr.py \
  --binary src/guardiabox/ui/tauri/src-tauri/target/release/guardiabox-sidecar.exe \
  --gui-binary "/c/Program Files/GuardiaBox/GuardiaBox.exe" \
  --json
```

Persist as `nfr-report-local.json` (gitignored).

### 9.8 Anti-oracle smoke test (manual)

After unlocking the vault, encrypt a small file with one password and
attempt to decrypt with a wrong password. The error toast must show
the generic anti-oracle string -- never an exception class name,
never a stack trace, never a hint about which step failed
(cf. ADR-0015).
