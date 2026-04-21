# 0010 — Apache License 2.0 for the project

- Status: accepted
- Date: 2026-04-20
- Deciders: @sachamarlov, Claude Opus 4.7
- Tags: [legal, distribution]

## Context

The project is academic in origin but is intended to live on as a portfolio
asset and possibly be published or embedded in commercial work. We need a
license that:

1. Permits closed-source redistribution.
2. Provides explicit patent grant (the project ships cryptographic primitives).
3. Is widely understood, OSI-approved, and compatible with most ecosystems.
4. Carries no copyleft obligation (we do not want every consumer of
   GuardiaBox to be forced to release source).

## Considered options

- **A. Apache License 2.0** — patent grant, permissive, widespread adoption,
  trademark clause, NOTICE requirement.
- **B. MIT** — minimal, permissive, but **no explicit patent grant**.
  Cryptographic projects benefit from Apache's patent clarity.
- **C. BSD-3-Clause** — similar to MIT, no patent grant either.
- **D. GPL-3.0** — copyleft. Forbids closed-source re-use. Out of scope.
- **E. AGPL-3.0** — strong copyleft including network use. Out of scope.
- **F. MPL-2.0** — file-level copyleft. Compromise; less common in the
  Python / Tauri ecosystem.

## Decision

Adopt **option A — Apache License 2.0**. The full text is committed at
`/LICENSE`. The copyright notice reads `Copyright 2026 Sacha Marlov`.

## Consequences

**Positive**

- Anyone (including a future commercial GuardiaBox-derived product) can
  link, modify, and redistribute the code under their own terms, provided
  they preserve the LICENSE/NOTICE files and document modifications.
- The patent grant in §3 deters frivolous patent litigation.
- Compatibility: Apache 2.0 is one-way compatible with GPL-3+.

**Negative**

- Does not **force** downstream contributors to re-open improvements
  (different from copyleft licenses); we accept this as the cost of
  permissiveness.
- The NOTICE-file convention adds a small redistribution requirement.

## References

- Apache License 2.0 — https://www.apache.org/licenses/LICENSE-2.0
- OSI license overview — https://opensource.org/licenses
- "How to choose a license" — https://choosealicense.com/
