# 0008 — Spec-Driven Development workflow

* Status: accepted
* Date: 2026-04-20
* Deciders: @sachamarlov, Claude Opus 4.7
* Tags: [process, ai-collaboration]

## Context

When an AI agent contributes code at the speed and breadth Claude Code
operates at, the bottleneck shifts from "writing code" to "validating
intent". We need a checkpointing mechanism that lets the human approve
*what* will be built before the agent begins building.

## Considered options

* **A. Spec-Driven Development (SDD)** as popularised by GitHub Spec Kit
  (Microsoft, 2026): three files per feature — `spec.md` (behaviour),
  `plan.md` (technical approach), `tasks.md` (atomic breakdown).
* **B. Issue-only workflow** — every feature gets a GitHub issue; the agent
  works from that. Slimmer, but issues are noisy and don't version with the
  code.
* **C. No formal workflow** — rely on conversation history and PR
  descriptions. Doesn't scale beyond a couple of features.

## Decision

Adopt **option A**. Each non-trivial feature gets a directory under
`docs/specs/NNN-<feature>/` with `spec.md`, `plan.md`, and `tasks.md`. The
agent writes the spec first, the human reviews, then the agent implements.

## Consequences

**Positive**

* The human keeps "what to build" control without needing to micro-manage
  "how to build".
* Reviews are easier — you read the spec once, then trust the diff against
  the plan.
* Specs are committed alongside code; future readers see the full intent.

**Negative**

* Up-front cost per feature (~30 minutes to draft the trio).
* Risk of bureaucracy if applied to trivial changes — confine SDD to features
  that change behaviour or touch security.

## References

* GitHub Spec Kit — https://github.com/github/spec-kit
* Microsoft for Developers blog — https://developer.microsoft.com/blog/spec-driven-development-spec-kit
* Martin Fowler on SDD — https://martinfowler.com/articles/exploring-gen-ai/sdd-3-tools.html
