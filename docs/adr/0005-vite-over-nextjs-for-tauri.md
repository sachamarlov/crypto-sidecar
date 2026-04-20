# 0005 — Vite over Next.js for the Tauri frontend

* Status: accepted
* Date: 2026-04-20
* Deciders: @sachamarlov, Claude Opus 4.7
* Tags: [frontend, build]

## Context

Tauri 2 ships static assets bundled in the binary; there is no Node server
at runtime. Choosing a frontend framework that *requires* SSR therefore
adds friction without benefit.

## Considered options

* **A. Vite 6 + React 19 + TanStack Router** — SPA-native, ESM-first,
  HMR < 50 ms, recommended by Tauri docs.
* **B. Next.js 15 (SSG mode)** — must use `next export`; loses API routes,
  middleware, dynamic image optimisation; lazy-loading routes irrelevant on
  desktop.
* **C. Rsbuild (Rspack-based)** — Vite-equivalent, written in Rust, smaller
  ecosystem of plugins.
* **D. Express / custom Node server** — out of scope (no Node at runtime).

## Decision

Adopt **option A**.

## Consequences

**Positive**

* Build pipeline is minimal: `vite build` → static folder → embedded by
  Tauri. No SSR lifecycle to think about.
* Hot reload during development is sub-50 ms.
* The TanStack ecosystem (Router/Query/Table) gives end-to-end type safety
  without buying into Next's opinionated conventions.

**Negative**

* No file-based routing out of the box (TanStack Router fills that role).
* If we ever needed a *companion* web app (we don't), we'd need a separate
  setup.

## References

* Tauri Frontend Configuration — https://v2.tauri.app/start/frontend/
* Tauri & Next.js discussion — https://github.com/tauri-apps/tauri/discussions/6083
