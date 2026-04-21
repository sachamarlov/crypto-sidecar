# 0012 — PyInstaller for MVP, planned migration to Nuitka post-CDC

- Status: accepted
- Date: 2026-04-21
- Deciders: @sachamarlov, Claude Opus 4.7
- Tags: [packaging, distribution, sidecar]

## Context and problem statement

The Python sidecar must be bundled as a single-file executable, shipped
inside the Tauri `.exe` via `tauri.conf.json > bundle.externalBin`.
Two mature tools compete in 2026, and a third is emerging:

- **PyInstaller** — bundles interpreter + `.pyc` + binary deps into a
  self-extracting archive.
- **Nuitka** — transpiles Python to C, compiles with MSVC/Clang/GCC
  into a native executable.
- **PyOxidizer** — embeds Python directly into a Rust binary.

The academic reviewer flagged the risk that "compilation with all these
dependencies will be painful." Investigation shows the concern is
partially outdated (modern `pyinstaller-hooks-contrib` covers our deps)
but contains a real residual risk worth documenting and mitigating.

## Considered options

### A. PyInstaller only (MVP path)

**Pros**

- Officially documented by Tauri 2 for the sidecar pattern.
- `pyinstaller-hooks-contrib >= 2024.10` (already pinned in
  `pyproject.toml`) covers every C-extension dep we use:
  `cryptography`, `argon2-cffi`, `SQLAlchemy`, `pydantic`, `FastAPI`,
  `uvicorn[standard]`.
- 4.76 M monthly PyPI downloads — 10 × Nuitka. Largest Stack Overflow
  coverage, smallest cost per unknown-unknown.
- Build time ~1 minute per OS — fast CI matrix iteration.

**Cons**

- Self-extracting archive pattern triggers Windows Defender false
  positives regularly (reputational for a vault app — a user cannot
  install something quarantined).
- Cold start extracts to `%TEMP%`, 2–5 s on SSD, 10–15 s on HDD.
- Produces ~90 MB binary (vs ~55 MB with Nuitka for the same code).
- `.pyc` bytecode in the bundle is trivially decompilable (weak code
  protection for a security product).

### B. Nuitka only (immediate switch)

**Pros**

- Native compiled binary — no false positives on AV.
- Cold start < 500 ms — noticeably faster.
- 2–4× runtime speed-up on pure Python code.
- Code is compiled to C then linked, meaningfully harder to reverse.
- Automatic detection of dynamic imports (no manual `--hidden-import`).

**Cons**

- 3–5 × longer build time (C compilation).
- Not mentioned in Tauri 2 official sidecar documentation — we would
  be paving new ground.
- Half a million monthly downloads — 10 × less Stack Overflow, more
  unknown-unknowns.
- 1–2 days of initial setup effort that the CDC deadline (2026-04-29)
  cannot afford to lose.

### C. PyInstaller now, planned migration to Nuitka post-CDC (**chosen**)

**Pros**

- Ships fast for the CDC deliverable with the documented Tauri path.
- Commits in writing to a concrete quality upgrade, preventing this
  decision from silently becoming permanent.
- Migration cost is bounded — PyInstaller and Nuitka share similar
  spec-file semantics ; the Python code itself needs no change.

**Cons**

- Carries the PyInstaller downsides (AV false positives, slower cold
  start, bigger binary) for the duration of the MVP window.
- Requires discipline to actually perform the migration.

### D. PyOxidizer

**Pros**

- Would embed the Python runtime directly inside the Tauri Rust
  binary, eliminating the sidecar-as-external-process entirely.
- Smallest possible binary footprint.

**Cons**

- Ecosystem is much less mature — `cryptography` and other C-extension
  packages are known to be fragile under PyOxidizer.
- Adds a Rust dependency tree to the sidecar side, doubling the
  mental model.
- Not in a state to ship for a 2026-04-29 deadline.

## Decision

Adopt **Option C — PyInstaller now, planned migration to Nuitka
post-CDC**.

### Concrete invariants

1. `scripts/build_sidecar.py` uses PyInstaller for the 29/04 release
   build. The exact invocation is documented in
   `docs/specs/000-tauri-sidecar/plan.md`.
2. A follow-up ticket is opened in the project backlog: **"Migrate
   sidecar packaging to Nuitka"**, with the following acceptance
   criteria:
   - Drop-in replacement on every CI matrix entry.
   - Binary size reduced by ≥ 30 % vs the PyInstaller baseline.
   - No Windows Defender false positive on a freshly-installed
     Windows 11 VM with default policy.
   - Cold start < 1 s measured on a reference SSD.
3. The migration must ship **before any public v1.0 release** of
   GuardiaBox, regardless of academic timeline.

### Explicit triggers for earlier migration

Any of the following conditions will escalate the Nuitka migration
ahead of the "post-CDC" schedule:

- Windows Defender blocks the PyInstaller binary on the demo machine
  before 2026-04-29.
- A user-reported bug shows `%TEMP%` extraction race conditions on
  slow disks.
- Cold-start time exceeds 8 s on the reviewer's laptop.

## Consequences

**Positive**

- Predictable build pipeline for the MVP using well-documented tools.
- Migration path is traced and contractualised — no silent tech debt.
- The Python source code is 100 % compatible with both tools, so the
  migration is a build-system change, not a code rewrite.

**Negative**

- MVP ships with the known PyInstaller downsides. The project tracks
  them explicitly rather than pretending they do not exist.
- A future commit of energy is owed (Nuitka migration PR).

## References

- [PyInstaller 6.x stable hooks](https://pyinstaller.org/en/stable/hooks.html)
- [Nuitka official documentation](https://nuitka.net/)
- [Tauri 2 sidecar pattern](https://v2.tauri.app/develop/sidecar/)
- [PyInstaller vs Nuitka vs cx_Freeze 2026 comparison](https://ahmedsyntax.com/2026-comparison-pyinstaller-vs-cx-freeze-vs-nui/)
- [Compilation vs Bundling — Nuitka vs PyInstaller (KRRT7)](https://krrt7.dev/en/blog/nuitka-vs-pyinstaller)
- [DeepMind's use of Nuitka (research utilities)](https://github.com/Nuitka/Nuitka#readme)
