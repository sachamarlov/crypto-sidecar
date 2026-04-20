<!--
Title must follow Conventional Commits:
  feat(scope): …
  fix(scope): …
  docs(scope): …
  refactor(scope): …
  chore(scope): …
-->

## Summary

<!-- 1-3 bullet points describing the *intent* of this change. -->

-
-

## Linked spec / ADR

<!-- If this touches architecture: link the ADR under docs/adr/.
     If this implements a feature: link the spec under docs/specs/<NNN>/. -->

- [ ] Spec: `docs/specs/<NNN-feature>/`
- [ ] ADR: `docs/adr/<NNNN-title>.md`
- [ ] Threat model impact reviewed: `docs/THREAT_MODEL.md`
- [ ] Crypto decisions impact reviewed: `docs/CRYPTO_DECISIONS.md`

## Test plan

<!-- A checklist of concrete actions the reviewer can reproduce. -->

- [ ] `uv run pytest` passes locally
- [ ] `uv run ruff check` passes
- [ ] `uv run mypy src` passes
- [ ] `uv run bandit -r src` passes
- [ ] Relevant property-based tests added under `tests/property/`

## Security self-review

- [ ] No secrets logged, printed, or committed.
- [ ] All user paths resolved via `fileio.safe_path`.
- [ ] All tag comparisons via `hmac.compare_digest`.
- [ ] Password buffers zero-filled post-use.
- [ ] Any new dependency has been audited (`pip-audit` / `npm audit`).

## Breaking changes

- [ ] None
- [ ] Yes — details below (triggers `BREAKING CHANGE:` footer + major bump)

<!--
Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
-->
