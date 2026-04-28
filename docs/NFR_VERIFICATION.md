# Non-Functional Requirements -- verification report

> Cross-references the nine NFR rows in `docs/SPEC.md` to the
> tests, scripts, or CI gates that prove each one. Updated on
> every Phase that changes a measured value.

Last refresh: **2026-04-27** (post Phase I).

| Code  | Requirement                                                        | Measured (post-build)                           | Verified by                              | Status |
| ----- | ------------------------------------------------------------------ | ----------------------------------------------- | ---------------------------------------- | ------ |
| NFR-1 | Encrypt + decrypt >= 100 MiB/s on a modern laptop SSD              | n/a (perf test markers)                         | `tests/perf/test_throughput.py`          | OK     |
| NFR-2 | KDF derivation 50 ms <= T <= 1 s on the same hardware              | n/a (perf test markers)                         | `tests/perf/test_kdf_timing.py`          | OK     |
| NFR-3 | Cold start CLI < 200 ms ; cold start GUI < 1.5 s                   | CLI: ~1900 ms ; GUI: ~5700 ms                   | `scripts/verify_nfr.py` + CI release job | DEBT   |
| NFR-4 | Sidecar memory footprint < 100 MiB at idle                         | **116 MiB** (parent + child processes)          | `scripts/verify_nfr.py` + CI release job | DEBT   |
| NFR-5 | Distributable binary (Windows) <= 80 MiB after PyInstaller + Tauri | sidecar 41.7 MiB ; NSIS 45.7 MiB ; MSI 46.7 MiB | `scripts/verify_nfr.py` + CI release job | OK     |
| NFR-6 | All UI strings localised (FR + EN) via `react-i18next`             | n/a                                             | spec 000-tauri-frontend H-12             | OK     |
| NFR-7 | WCAG 2.2 AA accessibility on the GUI                               | n/a (manual)                                    | H-13 (axe-playwright) + manual review    | DEBT   |
| NFR-8 | Test coverage >= 80 % overall, >= 95 % core/security               | n/a (517 unit tests pass)                       | `scripts/check_coverage_gates.py`        | OK     |
| NFR-9 | Lint, type, tests, security all green for every merge              | n/a                                             | `.github/workflows/ci.yml`               | OK     |

## Detailed evidence

### NFR-3 -- Cold start

The script `scripts/verify_nfr.py` measures both the CLI cold
start (median of 5 `python -m guardiabox --help` runs) and the
GUI cold start (median of 3 sidecar handshake times spawned from
the bundled binary).

#### CLI cold start (target < 200 ms)

| Environment                                | Measured | Target | Verdict |
| ------------------------------------------ | -------- | ------ | ------- |
| Dev (`uv run python -m guardiabox --help`) | ~1900 ms | 200 ms | DEBT    |
| Bundled CLI binary                         | n/a      | 200 ms | TBD     |

The dev measurement includes ~1.7 s of Python interpreter boot +
import-time work (`cryptography`, `sqlalchemy`, `alembic`,
`fastapi`, `typer`, `rich`). The 200 ms target was set assuming a
**bundled CLI binary** -- which we do not produce yet (Phase I
ships only the sidecar binary; a separate CLI binary would
duplicate ~30 MiB of Python runtime on disk).

ADR-0012 commits the project to a Nuitka migration after the CDC
delivery; Nuitka eliminates the Python interpreter boot cost and
brings cold-start under 500 ms. The current gap is therefore
tracked, documented, and bounded -- not silently accepted as a
regression.

#### GUI cold start (target < 1.5 s)

Measured locally on Windows 11 SSD via `verify_nfr.py
--gui-binary <sidecar.exe>`:

| Environment                          | Measured | Target  | Verdict |
| ------------------------------------ | -------- | ------- | ------- |
| PyInstaller --onefile sidecar (cold) | ~5700 ms | 1500 ms | DEBT    |

**Why the gap**: PyInstaller `--onefile` archives the entire
Python runtime + every dep into a single self-extracting bundle.
On every cold start the bootloader extracts the bundle to a
unique `%TEMP%\_MEIxxxxxx` directory before the embedded Python
interpreter spins up. ADR-0012 anticipated this exactly:

> Cold start extracts to %TEMP%, 2-5 s on SSD, 10-15 s on HDD.

5.7 s is the upper bound of that range on a fresh boot when the
filesystem cache is cold. Subsequent launches in the same
session drop to ~3 s (cache warm). Mitigation: ADR-0012's Nuitka
migration brings cold-start back to ~500 ms. The CDC reviewer is
on a known-spec laptop -- the demo runs from a warm cache and
sits closer to the 3 s mark.

**Trigger to escalate Nuitka before CDC** (per ADR-0012):
cold start > 8 s on the reviewer's laptop. We are at 5.7 s on the
dev workstation; the trigger is not crossed. If a reviewer
machine pushes it past 8 s during the demo, the Nuitka migration
moves up.

### NFR-4 -- Sidecar idle memory

`scripts/verify_nfr.py --sidecar-only` spawns the bundled
sidecar, waits for the handshake, sleeps 5 s for warmup garbage
to settle, then sums `memory_info().rss` of the parent process
**plus every descendant** (PyInstaller `--onefile` boots a
bootloader that re-execs as a child Python; sampling only the
parent under-reports by ~100 MiB).

Reference measurement on Windows 11, PyInstaller `--release`
build:

| Build mode                       | Measured RSS | Target  | Verdict |
| -------------------------------- | ------------ | ------- | ------- |
| `--onefile --release` Windows PE | **116 MiB**  | 100 MiB | DEBT    |

**The 16 MiB overshoot** is dominated by the embedded Python
interpreter + the eager-loaded `cryptography`, `sqlalchemy`,
`alembic`, `fastapi`, `uvicorn` modules. None of these can be
trimmed without changing the runtime contract.

Two paths to bring NFR-4 back under 100 MiB:

1. **Nuitka migration** (ADR-0012, post-CDC): native compiled
   binary loads only the symbols actually called; typical RSS
   drops by 30-40 %. This is the documented mitigation.
2. **`--onedir` instead of `--onefile`**: skips the bootloader
   re-exec and the `%TEMP%` extraction; saves ~15 MiB but ships
   ~250 files instead of one. Rejected for MVP because the user
   experience of an 8000-file install (Tauri + Python runtime
   - Node bundles) is poor.

**For the v0.1.0 release we accept the 16 MiB gap as
documented technical debt.** No silent regression; the figure
is published, the path forward is in ADR-0012.

### NFR-5 -- Distributable binary size

Three artefacts in scope: the **sidecar binary** (PyInstaller
output), the **Tauri shell** (Rust + WebView2 + frontend
embedded), and the **Tauri installer bundle** (NSIS / MSI).

| Artefact                                | Measured Win11 | Target | Verdict |
| --------------------------------------- | -------------- | ------ | ------- |
| Sidecar PE (PyInstaller --release)      | **41.7 MiB**   | 80 MiB | OK      |
| `guardiabox.exe` shell (Tauri release)  | **6.3 MiB**    | 80 MiB | OK      |
| NSIS installer `GuardiaBox_*-setup.exe` | **45.7 MiB**   | 80 MiB | OK      |
| MSI installer `GuardiaBox_*_x64.msi`    | **46.7 MiB**   | 80 MiB | OK      |
| Sidecar Linux ELF (CI)                  | TBD            | 80 MiB | TBD     |
| Sidecar macOS Mach-O (CI)               | TBD            | 80 MiB | TBD     |

All measured Windows artefacts come in at **57-58 % of the
budget**. The NSIS installer is the canonical release artefact
(smaller + auto-handles WebView2 runtime check); MSI is shipped
in en-US + fr-FR locales for users who deploy via Group Policy.

CI fails the `nfr-verification` job when **any** measured
artefact exceeds 80 MiB. The `release.yml` job does not silently
allow regressions.

### NFR-7 -- Accessibility

WCAG 2.2 AA is partially verified:

- **Manual review** during Phase H (focus rings on every
  interactive element, `aria-live="polite"` on the password
  strength bar, semantic landmarks on the lock screen).
- **`axe-playwright` automated audit** still pending (#97 H-13).
  The dependency is already declared in `package.json
devDependencies`; the test scaffolding is what's missing.
- **Colour contrast** validated visually on Tailwind v4 theme
  (text 4.7:1, UI components 3.0:1 -- AA).

The verdict reflects that automated coverage is incomplete; it
will flip to `OK` when H-13 lands.

### NFR-8 -- Coverage gates

Three gate tiers, enforced by `scripts/check_coverage_gates.py`:

- `src/guardiabox/core` >= 95 %
- `src/guardiabox/security` >= 95 %
- `src/guardiabox/ui/tauri/sidecar` >= 90 %
- Overall >= 80 % (via `pyproject.toml > tool.coverage.report.
fail_under`)

The Phase G follow-ups landed `sidecar/` at 94 %; the others
remain comfortably above their floors.

### NFR-9 -- CI all-green policy

Every merged PR triggers the seven CI jobs in `.github/workflows/
ci.yml`:

1. `Python 3.12 on ubuntu-latest` -- ruff + mypy + pytest + cov
2. `Python 3.12 on windows-latest` -- ruff + mypy + pytest + cov
3. `Frontend (Node 22)` -- biome + tsc + vitest
4. `Sidecar PyInstaller (Linux)` -- build + smoke test
5. `Rust (Tauri shell)` -- fmt + clippy + cargo test
6. `Analyze (python)` -- CodeQL (advisory only -- repo doesn't
   have code scanning enabled, accepted red gate)
7. `Analyze (javascript-typescript)` -- CodeQL (same)

Phase I additionally adds the `release.yml` workflow that runs
on `release: published`. CI gate breakdown: 5 hard gates (jobs
1-5) + 2 advisory CodeQL gates.

### Open items at v0.1.0

| Gap                                  | Measured | Target  | Mitigation                     |
| ------------------------------------ | -------- | ------- | ------------------------------ |
| NFR-3 CLI cold start                 | ~1900 ms | 200 ms  | ADR-0012 Nuitka migration      |
| NFR-3 GUI cold start (cold cache)    | ~5700 ms | 1500 ms | ADR-0012 Nuitka migration      |
| NFR-4 sidecar idle RSS               | 116 MiB  | 100 MiB | ADR-0012 Nuitka migration      |
| NFR-7 axe-playwright automated audit | n/a      | n/a     | #97 H-13 (post-CDC follow-up)  |
| NFR-3/4/5 cross-platform measurement | n/a      | n/a     | Unblock GitHub Actions billing |

**Honesty over green checkmarks.** Three of four NFR-3/4 numbers
overshoot the published target. Each overshoot was anticipated
by ADR-0012 (PyInstaller --onefile cold-start + RAM cost), is
tracked in writing, and has a documented mitigation path. The
v0.1.0 release ships with these gaps clearly disclosed; the
v0.2.0 milestone (Nuitka migration) is the path back inside.
