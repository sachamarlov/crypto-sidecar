# 0006 — `uv` over Poetry / pip for Python dependency management

* Status: accepted
* Date: 2026-04-20
* Deciders: @sachamarlov, Claude Opus 4.7
* Tags: [tooling, python]

## Context

Three serious options exist in 2026 for managing Python projects: `pip` +
`venv` + `requirements.txt`, Poetry, and Astral's `uv`. We need fast cold
installs (CI matters), a deterministic lockfile that works cross-platform,
and minimal configuration noise.

## Considered options

* **A. `uv`** (Astral) — Rust-based; manages Python versions, virtualenvs,
  dependencies, lockfile, build, publish, all in one. 10–100× faster than
  pip/poetry. `uv.lock` is committed and cross-platform.
* **B. Poetry** — mature, plugin ecosystem, decent UX. Slower than uv.
* **C. pip + venv + requirements.txt + pip-tools** — standard but no native
  cross-platform lockfile, more discipline required.

## Decision

Adopt **option A**. The repo commits `uv.lock` and `.python-version`.

## Consequences

**Positive**

* CI installs go from "minutes" to "seconds".
* One tool covers Python version, virtualenv, deps, build, publish.
* Same tool used to bundle the sidecar via `uv tool run pyinstaller`.

**Negative**

* `uv` is younger than Poetry; some niche plugins don't exist (we don't
  need any).
* Contributors used to Poetry need a 5-minute on-ramp (documented in
  `DEVELOPMENT.md`).

## References

* uv documentation — https://docs.astral.sh/uv/
* Python Project Setup 2026 — https://www.kdnuggets.com/python-project-setup-2026-uv-ruff-ty-polars
