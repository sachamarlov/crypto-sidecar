---
status: accepted
date: 2026-04-29
deciders: Sacha Marlov + Claude Opus 4.7 (autonomy mode)
---

# ADR-0017 — Frontend state management: Jotai + Zustand + TanStack Query

## Context

The Tauri 2 + React 19 frontend (Phase H) needs a state strategy
that separates three concerns:

1. **Lock state** (sessionId, expiresAtMs, isUnlocked, activeUserId).
   Read by `<AuthGuard>`, `useAutoLock`, every authenticated `fetch`.
   Mutation must trigger immediate re-render of the auth guard but
   *not* re-render unrelated UI on every lock-tick.
2. **UI globals** (current language, theme preference, transient
   toasts, persistent localStorage). Long-lived, cross-tab via
   localStorage if the user opens a second window in dev.
3. **Server cache** (users list, audit entries, doctor report).
   Subject to revalidation, optimistic updates, refetch on focus,
   stale-while-revalidate semantics.

A single Redux slice would mix the three concerns and force every
consumer to subscribe to the entire store; React Context alone
re-renders every child on every change. The frontend tasks list
(`docs/specs/000-tauri-frontend/tasks.md`) referenced this ADR as
"candidate" while the implementation landed without a written ADR.

## Decision

We split state by lifetime:

| Layer | Library | Persistence |
|-------|---------|-------------|
| Lock atoms | **Jotai 2** (`atom`, `useAtomValue`, `useAtom`) | In-memory only; cleared on lock |
| UI globals | **Zustand 5** with `persist` middleware | localStorage (key `guardiabox.lang` etc.) |
| Server cache | **TanStack Query 5** | None (refetch policy per query) |

**Jotai** is fine-grained: `useAtomValue(isUnlockedAtom)` only re-
renders when that derived atom flips. The auth guard uses it; the
auto-lock countdown reads `expiresAtMsAtom` independently.

**Zustand** is one store per concern (`useLanguageStore`,
`useThemeStore` later). The `persist` middleware writes to
`localStorage` on each `set()`, syncs across windows via the
`storage` event.

**TanStack Query** owns every server fetch (`useReadyz`, `useUsers`,
`useAudit`, etc.). Mutations (`useUnlock`, `useCreateUser`)
invalidate query keys on success.

## Consequences

* **Three libraries instead of one.** Bundle size cost: ~6 KiB Jotai
  + 1 KiB Zustand + ~14 KiB TanStack Query (already a dep for the
  query layer). Total <25 KiB gzip, acceptable for the desktop bundle.
* **Mental overhead.** Contributors must know which layer to use:
  is this server-fetched? → TanStack Query. Is this lock-scoped? →
  Jotai. Is this localStorage-persistent? → Zustand. The README
  + this ADR codify the rule.
* **No cross-layer transactions.** A lock action that needs to
  invalidate every server query *and* clear UI state requires
  three explicit calls (`queryClient.clear()`, `setSessionId(null)`,
  `useLanguageStore.persist.clearStorage()`). δ-5 / δ-6 implement
  this.
* **`activeUserIdAtom`** lives in Jotai despite the docstring
  initially mentioning a `/users/{id}/unlock` endpoint that does
  not exist. The atom is purely a client-side selector for the
  share/accept flows; per-user RSA-private unwrap happens server-
  side at share/accept time (ADR-0004).

## Alternatives considered

* **Redux Toolkit**: rejected for the boilerplate and the global
  re-render cost on every action.
* **Zustand-only**: it can carry server cache (with manual
  refetch), but reinventing TanStack Query's invalidation +
  optimistic mutations was out of scope.
* **TanStack Store** (still alpha at 2026-04-29): tracked for a
  future migration once it stabilises and ships persist middleware.
