# 0007 — Conventional Commits enforced by `release-please`

- Status: accepted
- Date: 2026-04-20
- Deciders: @sachamarlov, Claude Opus 4.7
- Tags: [process, release]

## Context

We need a commit-message convention that is human-readable, parseable by
tooling, and that lets us automate the changelog and the version-bump cycle.

## Considered options

- **A. Conventional Commits + `release-please`** (Google).
- **B. Semantic Release (semantic-release/semantic-release)**. JS-centric,
  more configuration, plugin sprawl.
- **C. Free-form messages, manual changelog.** Predictable rot.

## Decision

Adopt **option A**. The `commit-msg` pre-commit hook
(`compilerla/conventional-pre-commit`) refuses non-conforming messages.
`release-please-action` opens a "release PR" that aggregates pending changes
and bumps the version on merge.

## Consequences

**Positive**

- `CHANGELOG.md` is automatic, never manually edited (besides typos).
- Versioning is consequence of the commit history (`feat:` → minor; `fix:` →
  patch; `BREAKING CHANGE:` → major).
- AI agents and humans share the same convention; commit history is greppable.

**Negative**

- Strict commit format is mildly annoying initially; the hook fails fast and
  helpfully.
- Commits authored by an AI must include the `Co-Authored-By:` trailer; this
  is encoded in the project's commit-message template.

## References

- Conventional Commits — https://www.conventionalcommits.org/
- `release-please` — https://github.com/googleapis/release-please
