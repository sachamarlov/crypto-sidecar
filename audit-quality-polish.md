# Audit Code Quality + UX Polish (E) -- 2026-04-29

> Auditor lens: Senior Dev + UX Designer + Reviewer obsessed with detail.
> Comparison anchors: 1Password, Bitwarden, Dashlane.
> Scope: transverse READ-ONLY pass on frontend (React 19), backend
> (Python sidecar), Rust shell, scripts, docs.
> Soutenance: tomorrow.

## Executive Summary

**Verdict général : mid (75% pro / 25% étudiant), with two amateur signals
that show up in the first 10 seconds of demo.** The crypto core
(`core/operations.py`, `core/crypto.py`, `share_token.py`, `keystore.py`)
is genuinely senior-level: explicit AAD construction, anti-oracle
discipline (ADR-0015, ADR-0016 §C), zero-fill ceremony in `finally`
blocks, NFC password normalisation. The infra surface (CI, NFR
verification, ADR discipline, threat model, conventions doc) is well
above academic norm. **What sells "étudiant"**: (1) frontend
duplications and dead `App.tsx` bootstrap scaffold still in the bundle
(2) the dashboard UI looks like a Tailwind tutorial — no skeleton
loading, no error boundaries, no empty-state CTAs beyond
`dashboard.index`, no auto-lock countdown despite the doc claiming one
exists, no light-theme toggle despite the CSS being shipped. **The
biggest red flag for the jury** is `package.json`: 70+ dependencies
declared (Three.js, canvas-confetti, 20 Radix primitives, argon2-browser,
lenis, vaul, cmdk, react-hook-form + zod) of which **only 6 are
actually imported**. That ratio reads as "I copy-pasted a starter
template and never cleaned up". Storybook still in `devDependencies`
contradicts CHANGELOG Phase I claim "Storybook removed entirely".

---

## Findings P0 (visible at the soutenance — fix before)

### P0-1 — `App.tsx` is dead code shipped in production

- **File** : `C:\crypto-project\src\guardiabox\ui\tauri\frontend\src\App.tsx:1-52`
- **Catégorie** : code-quality, dead-code
- **Description** : The component declares `export function App()` with
  a "v0.1.0 — bootstrap scaffold" caption; `main.tsx` switched to
  `RouterProvider` and never imports `App` anywhere. `noUnusedLocals`
  catches unused variables but not unused exported components.
  Confirmed: `Grep -p "App"` matches only the file itself.
- **Impact** : the jury opens the project in the IDE, sees `App.tsx`
  as the obvious entry point per React convention, reads "bootstrap
  scaffold" — instant signal that work is unfinished. The file is
  also bundled by Vite (tree-shaking does not remove unimported
  exports because it's authored as a top-level file, although Vite
  may DCE — to verify we'd need to check the dist bundle).
- **Fix proposé** : `git rm src/App.tsx`.
- **CONVENTIONS.md sec 16** : "❌ No commented-out code ... or dead
  branches" — applies by spirit to dead modules.

### P0-2 — `package.json` declares ~70 dependencies, 6 actually imported

- **File** : `C:\crypto-project\src\guardiabox\ui\tauri\frontend\package.json`
- **Catégorie** : code-quality, dependency-bloat, security-surface
- **Description** : grep across `src/` confirms the only imported
  packages are `@tanstack/react-{query,router,query-devtools,router-devtools}`,
  `@tauri-apps/{api,plugin-dialog}`, `framer-motion`, `i18next` +
  `react-i18next` + `i18next-browser-languagedetector`, `jotai`,
  `lucide-react`, `next-themes`, `react`/`react-dom`, `sonner`,
  `tailwind-merge` + `clsx`, `tw-animate-css`, `zustand`. **Never
  imported anywhere**: `@radix-ui/react-{accordion, alert-dialog, avatar,
checkbox, context-menu, dialog, dropdown-menu, hover-card, label,
popover, progress, radio-group, scroll-area, select, separator,
slider, slot, switch, tabs, toast, tooltip}` (all 21 Radix packages),
  `@react-three/{drei, fiber, postprocessing}`, `three`,
  `canvas-confetti`, `lenis`, `vaul`, `cmdk`, `react-hook-form` +
  `@hookform/resolvers` + `zod`, `@tanstack/react-{table, virtual}`,
  `react-resizable-panels`, `react-hotkeys-hook`, `react-error-boundary`,
  `immer`, `argon2-browser`, `@noble/{ciphers, hashes}`, `@types/three`,
  `@types/canvas-confetti`, `class-variance-authority`,
  `@tauri-apps/plugin-{clipboard-manager, fs, global-shortcut,
notification, os, process, shell, store, updater, window-state}` (10
  plugins). Storybook ^8.6.18 is still in devDependencies despite
  CHANGELOG Phase I claiming "Storybook removed entirely".
- **Impact** :
  1. Bundle size: dev deps are stripped, runtime deps inflate the
     production bundle (Three.js alone is ~1 MB gzipped). NFR-5 still
     passes (45.7 MiB NSIS), but the jury reading the package.json
     during code review will count the lines.
  2. Security surface: `@noble/ciphers`, `@noble/hashes`,
     `argon2-browser` declared in **the UI layer** — directly
     contradicts CLAUDE.md sec 11: "❌ Importing crypto code in `ui/`
     layers directly (always go through `core/`)". Even if not
     imported, declaring them is a "we tried at some point" signal.
  3. CONVENTIONS.md sec 4 anti-pattern: "❌ Adding a dependency
     without a justifying ADR" — none of these are in `docs/adr/`.
  4. `pnpm audit` surface: every transitive dep is a future CVE.
- **Fix proposé** : `pnpm remove` every unused dep. Keep the working
  ones. Re-run `pnpm audit` after.
- **CHANGELOG inconsistency** : Storybook line says "removed entirely"
  but devDependencies still contains it.

### P0-3 — Hard-coded dark theme contradicts shipped light tokens

- **File** : `C:\crypto-project\src\guardiabox\ui\tauri\frontend\src\main.tsx:44`
  - `C:\crypto-project\src\guardiabox\ui\tauri\src-tauri\tauri.conf.json:31`
  - `C:\crypto-project\src\guardiabox\ui\tauri\frontend\src\index.css:5-27`
- **Catégorie** : ux-polish, dead-code
- **Description** : `index.css` lines 6-27 define a complete light-mode
  token set (`--background: oklch(0.98 0 0)`, etc.) but `main.tsx` sets
  `<ThemeProvider attribute="class" defaultTheme="dark" enableSystem>`
  while `tauri.conf.json` line 31 hard-codes `"theme": "Dark"`. There
  is **no UI control to toggle the theme** anywhere — no `useTheme()`
  reader, no toggle button. The light tokens are dead CSS. `next-themes`
  is loaded for nothing.
- **Impact** : jury asks "why is light mode missing?" or "why ship a
  theme system if not exposed?" — both reads as half-implemented work.
  1Password and Bitwarden both ship a Light/Dark/System triple.
- **Fix proposé** : either (a) add a theme toggle in `dashboard.tsx`
  header (next to the EN/FR button), or (b) delete the light tokens
  - remove `next-themes` + drop `attribute="class"` from main.tsx.
    Option (a) is the senior choice for a vault product.

### P0-4 — Zero React error boundaries — runtime exception = white screen

- **File** : entire `src/guardiabox/ui/tauri/frontend/src/`
- **Catégorie** : ux-polish, defensive-coding
- **Description** : `react-error-boundary` is declared in package.json
  but **never imported**. `__root.tsx:8-15` has no `errorComponent`,
  no `notFoundComponent`, no `onCatch`. TanStack Router supports
  `errorComponent` per route — none of the 9 routes set one. Every
  `onError` handler is a TanStack Query mutation handler, which only
  catches network errors, not render-time exceptions.
- **Impact** : a render exception (e.g. accessing
  `auditQuery.data.entries[0].timestamp` on a server returning a
  malformed entry) crashes the entire WebView2 to a blank page. The
  user has to kill GuardiaBox.exe and relaunch. 1Password shows a
  "Something went wrong — restart" overlay with a recover button.
- **Fix proposé** : import `react-error-boundary` (already in deps),
  wrap `<RouterProvider>` in `main.tsx` with `<ErrorBoundary
fallback={...}>` showing an "Une erreur est survenue. [Recharger]"
  card. ~30 lines.
- **CLAUDE.md sec 11** anti-pattern parallel: "Disabling a security
  rule for testing" — here it's "ignoring runtime safety because tests
  cover happy path only".

### P0-5 — Auto-lock kicks the user without warning, no countdown

- **File** : `C:\crypto-project\src\guardiabox\ui\tauri\frontend\src\hooks\useAutoLock.ts:16-37`
  - `src\stores\lock.ts:4-7`
- **Catégorie** : ux-polish
- **Description** : `useAutoLock` polls at 1 Hz (good) but the only
  state it writes is `setSessionId(null)` on expiry — there is **no
  visible countdown**. The user types in the encrypt form, leaves to
  fetch a coffee, comes back: AuthGuard has rerouted to `/lock` and
  the in-progress form data is lost. Worse, `lock.ts:4-7` doc claims
  "auto-lock countdown UI only re-renders when `expiresAtMsAtom`
  changes" — but **nothing reads `expiresAtMsAtom` to render a
  countdown**. The doc is aspirational.
- **Impact** : 1Password shows "Auto-lock dans 04:32" persistent in
  the header bar. Bitwarden idles a banner at 1 minute remaining. Our
  dashboard shows nothing — the lock is brutal and surprising.
- **Fix proposé** : add a `<AutoLockBadge />` to `dashboard.tsx`
  header. Subscribe to `expiresAtMsAtom`, recompute via `Date.now()`
  every second, render `mm:ss`. When < 60 s, switch to amber colour
  and add a "Reset countdown" button (any subsequent request hits the
  sliding TTL on the server side).

### P0-6 — No drag-drop on encrypt despite Tauri config enabling it

- **File** : `tauri.conf.json:28` (`"dragDropEnabled": true`) +
  `C:\crypto-project\src\guardiabox\ui\tauri\frontend\src\routes\dashboard.encrypt.tsx`
- **Catégorie** : ux-polish, missing-feature
- **Description** : `tauri.conf.json` enables drag-drop but no React
  component subscribes to `getCurrentWebview().onDragDropEvent()` or
  to native `onDrop` on a dropzone. Encrypt route line 67-89 ships a
  text input + "Choisir…" button. `Grep "onDrop"` returns zero.
- **Impact** : a Bitwarden user drags a PDF onto the GuardiaBox window
  and nothing happens — confusing because the window invites it
  (transparent + frameless). The most idiomatic crypto-tool UX is "drop
  here to encrypt". This is the single highest-impact UX fix in <1h.
- **Fix proposé** : in `dashboard.encrypt.tsx`, add a `<DropZone />`
  region above the path input. Listen to `getCurrentWebview()
.onDragDropEvent()` (Tauri 2 API); on `'drop'` event, set
  `path = paths[0]` and surface a `toast.success("Fichier déposé")`.
  ~25 lines.

### P0-7 — Password strength labels hard-coded French, ignore i18n

- **File** : `C:\crypto-project\src\guardiabox\ui\tauri\frontend\src\lib\password.ts:31-37`
- **Catégorie** : i18n, code-quality
- **Description** : `LABEL_BY_SCORE` is a French-only `Record<0|1|2|3|4,
string>` (lines 31-37). The whole rest of the app uses
  `react-i18next` with FR/EN files at `src/i18n/{fr,en}.json`.
  Switching language to EN keeps the strength bar labelled "Très
  faible". `PasswordField.tsx:81` displays `evaluation.label` as-is.
- **Impact** : NFR-6 ("All UI strings localised (FR + EN) via
  `react-i18next`") **fails for this UI string**. NFR_VERIFICATION.md
  claims NFR-6 OK — false.
- **Fix proposé** : remove `LABEL_BY_SCORE` literal, expose only
  `score` from `evaluatePassword`, let `PasswordField.tsx` resolve
  `t(`password.strength\_${evaluation.score}`)`. Add the 5 keys to both
  i18n JSON files.

### P0-8 — Empty states almost everywhere absent

- **Files** :
  - `routes\dashboard.history.tsx:85-89` — has empty state ("Aucune
    entrée d'audit") with shield icon. **Good, keep.**
  - `routes\dashboard.users.tsx:108-133` — list rendered but no empty
    state for `users.length === 0` after first user creation. The
    create-user form sits above an invisible list.
  - `routes\dashboard.index.tsx:24-37` — has empty state for first-run.
    **Good, keep.**
  - `routes\dashboard.share.tsx`, `dashboard.accept.tsx` — no copy
    explaining what happens when there are no other users to pick
    (only the active user as recipient is filtered out
    `share.tsx:34-35`); empty `<select>` shows just `--`.
- **Catégorie** : ux-polish
- **Impact** : a fresh install with one user opens "Partager" and
  sees an unusable form. 1Password shows "Vous êtes seul utilisateur
  — créez d'abord un destinataire dans `Utilisateurs`" with a CTA
  link. We show a dropdown with `--`.
- **Fix proposé** : in `share.tsx` and `accept.tsx`, branch on
  `otherUsers.length === 0`, render a card with `<UserPlus/>` icon and
  a `<Link to="/dashboard/users">{t("share.no_recipients_cta")}</Link>`.

### P0-9 — Tauri capabilities expose 9 plugin permission groups for nothing

- **File** : `C:\crypto-project\src\guardiabox\ui\tauri\src-tauri\capabilities\default.json`
  - `src-tauri\src\lib.rs:25-35` + `Cargo.toml:21-30`
- **Catégorie** : security-surface, dead-code
- **Description** : capabilities/default.json registers permissions
  for `notification:*`, `clipboard-manager:*`, `store:*`,
  `window-state:*`, `global-shortcut:*`, `os:*`, `shell:*`, `fs:*` —
  all of which are loaded in `lib.rs` and listed in `Cargo.toml` as
  Rust deps, but **none is invoked from the React layer**. The doc
  block at line 4 says "Permissions are listed individually rather
  than via plugin bundles so the attack surface is auditable and
  resharpened on every PR. Add new entries only when a feature spec
  demands them; never widen blindly with `<plugin>:default`." —
  **but the file already widens blindly** with `fs:default`,
  `notification:default`, `store:default`, `window-state:default`.
- **Impact** : the doc-comment is aspirational, the practice
  contradicts it. A reviewer running `grep` will catch this in 30s.
  Each unused plugin adds Rust deps (Cargo build slower), Tauri IPC
  surface (CSP `connect-src` widened with `tauri://` channels), and
  an SBOM line.
- **Fix proposé** : remove the 9 unused plugins from `lib.rs:26-35`,
  drop the Cargo.toml deps, prune `capabilities/default.json` down to
  `core:*` + `dialog:*`. Re-run `cargo build`. Saves ~2-3 MB in the
  shell binary.

### P0-10 — `_settings` / `_store` duplicated 4× across sidecar routers

- **Files** :
  - `sidecar\api\v1\encrypt.py:78-80` — `_settings`
  - `sidecar\api\v1\decrypt.py:84-86` — `_settings`
  - `sidecar\api\v1\vault.py:76-78` — `_settings`, `81-83` — `_store`
  - `sidecar\api\dependencies.py:45-48` — `settings_dep`, `51-54` —
    `store_dep` (the **canonical** version, exported in `__all__`)
- **Catégorie** : code-quality, DRY violation
- **Description** : `dependencies.py` already exports `settings_dep`
  and `store_dep`. `users.py` + `share.py` + `audit.py` use them
  correctly. **The first three routers shipped privately copied
  helpers** — pure DRY violation per CONVENTIONS.md sec 2 ("Rule of
  Three: extract on the third occurrence"). Here we are at occurrence
  4, with the canonical version sitting one folder up.
- **Impact** : the four copies will drift independently. Already
  visible: `vault.py` defines `_store` returning `SessionStore` while
  `dependencies.py:51-54` types it the same — coincidence today, bug
  tomorrow when one ages.
- **Fix proposé** : delete `_settings` from `encrypt.py`, `decrypt.py`,
  `vault.py`; delete `_store` from `vault.py`; replace
  `Depends(_settings)` with `Depends(settings_dep)` (5 sites total).

---

## Findings P1 (post-soutenance early)

### P1-1 — `core/operations.py` is 915 lines (target: ≤500 file split)

- **File** : `core/operations.py`
- **Catégorie** : code-quality, file-too-large
- **Description** : the module bundles `inspect_container`,
  `encrypt_file`, `encrypt_message`, `decrypt_file`, `decrypt_message`,
  `share_file`, `accept_share` + 7 internal streaming helpers
  (`_encrypt_stream`, `_emit_chunk`, `_decrypt_stream`,
  `_decrypt_stream_plaintext`, `_decrypt_one`, `_split_message`,
  `_default_decrypt_dest`, `_zero_fill`, `_check_dest_not_existing`,
  `_password_bytes`). 915 lines is 1.8× the target.
- **Recommendation** : split into `core/operations/file.py` (encrypt
  / decrypt file), `core/operations/message.py` (in-memory message),
  `core/operations/share.py` (share/accept), `core/operations/_streaming.py`
  (private helpers). Public symbols stay re-exported from
  `core.operations` for backwards-compatibility.

### P1-2 — `encrypt_file` and `encrypt_message` share 70% scaffolding

- **Files** : `core/operations.py:162-261` (encrypt_file) +
  `264-328` (encrypt_message). Same pattern at decrypt level:
  `331-397` (decrypt_file) + `400-453` (decrypt_message).
- **Catégorie** : DRY (Rule of Three reached)
- **Description** : both functions repeat (a) `assert_strong`,
  (b) `kdf_impl = kdf if kdf is not None else DEFAULT_KDF()`,
  (c) `safe_target = resolve_within(...)`, (d) `_check_dest_not_existing`,
  (e) header construction with random salt + nonce,
  (f) `key_buf = bytearray(AES_KEY_BYTES)` + try/finally `_zero_fill`,
  (g) `cipher = AesGcmCipher(bytes(key_buf))`, (h) atomic_writer +
  write_header + `_encrypt_stream`. Same for decrypt path with
  `decrypt_message` calling `_decrypt_stream_plaintext` instead of
  `_decrypt_stream`. CONVENTIONS.md sec 2: "Rule of Three" says
  extract at the third occurrence — we are at the third (encrypt_file
  - encrypt_message + share_file calls into an inlined version).
- **Recommendation** : factor a `_with_derived_key(password, salt,
kdf, callback)` helper that handles steps (b)+(f)+(g) with the
  buffer ceremony, then `encrypt_file` and `encrypt_message` differ
  only in the chunk source. ~80 lines saved, easier to audit (one
  zero-fill site).

### P1-3 — Sidecar `Any` count + zero `# noqa: typing` annotations

- **Files** :
  - `logging.py:34`, `vault_admin.py:115`, `password.py:62,65,95`,
    `tui/widgets/toast.py:60`, `tui/screens/settings.py:21,22`,
    `cli/commands/{config,doctor,user}.py` (multiple),
    `sidecar/api/stream_hub.py:47,49`
- **Catégorie** : code-quality, type-strict
- **Description** : 16+ `Any` usages across the codebase. CLAUDE.md
  sec 4 mandates: "No `Any` without explicit `# noqa: typing` +
  comment." Grep across `src/` returns **zero** `# noqa: typing`
  annotations. Either justify each with a one-line comment or
  replace by a `TypedDict` / `Protocol` (e.g. `password.py:62` could
  type the zxcvbn return as a `TypedDict` of its known keys).

### P1-4 — `# type: ignore` markers across sidecar (9 occurrences)

- **Files** : `sidecar/app.py` (2), `sidecar/state.py` (1),
  `sidecar/api/v1/share.py` (6 — all `attr-defined` on a SQLAlchemy
  `User` row passed as `object`).
- **Catégorie** : code-quality, type-strict
- **Description** : `share.py:107-112` types `_keystore_from_user(user:
object)` because the function is invoked with an SA model row whose
  type leaks. Importing `User` from `persistence.models` and typing
  `user: User` removes all 6 ignores. The two in `app.py:42,49` are
  the `_DebugLogMiddleware` `__init__` and `dispatch` signatures —
  Starlette's BaseHTTPMiddleware uses untyped callables; the standard
  fix is `from starlette.types import ASGIApp` + `app: ASGIApp`.

### P1-5 — `users.py:show_user` and `delete_user` linear-scan instead of indexed lookup

- **File** : `sidecar/api/v1/users.py:92-108` (show_user) + `153-165`
  (delete_user) + `share.py:128-130, 200-203`
- **Catégorie** : code-quality, performance
- **Description** : `repo.list_all()` is called then a `next((u for u
in users if u.id == user_id), None)` linear scan happens. The
  `UserRepository` already exposes `get_by_username` (line 126); a
  symmetric `get_by_id(user_id)` is the natural complement. 4 sites
  invite an O(n) scan for a single-row read. With 50+ users the audit
  page becomes slow.
- **Recommendation** : add `UserRepository.get_by_id(user_id: str)
-> User | None`, replace the 4 linear scans.

### P1-6 — Dashboard mutations have no skeleton/spinner during load

- **Files** : every `routes/dashboard.*.tsx`
- **Catégorie** : ux-polish
- **Description** : the only loading hint is the submit button text
  swap to `t("common.loading")` (e.g. `lock.tsx:135`,
  `dashboard.encrypt.tsx:133`). For queries (users list, audit list),
  the pattern is `if (auditQuery.isLoading) return <p>{t("common.loading")}</p>;`
  — a flat text string with no skeleton. 1Password renders shimmer
  rows. Bitwarden has a card-shaped skeleton.
- **Recommendation** : add a `<Skeleton />` shadcn-style component
  (~10 lines: a `<div className="animate-pulse rounded bg-muted h-4
w-full" />`). Replace the 4-5 "Chargement…" `<p>` with skeleton
  rows matching the eventual layout.

### P1-7 — No success animation / confetti / system notification on encrypt

- **File** : `routes/dashboard.encrypt.tsx:50-54`
- **Catégorie** : ux-polish, missing-feature
- **Description** : on `onSuccess`, `toast.success("Fichier chiffré :
{{path}}")` then `navigate({ to: "/dashboard" })` — toast vanishes
  in 4s, user is back on the dashboard with no trace. `canvas-confetti`
  is in deps (sec P0-2 above) — could trigger 100ms confetti on a
  successful encrypt for delight. More importantly, `@tauri-apps/
plugin-notification` is loaded (lib.rs:30) — a system-tray
  notification on success would persist after the toast.
- **Recommendation** : invoke `Notification` with `await
isPermissionGranted()` then `sendNotification({ title: "GuardiaBox",
body: t("encrypt.success_notify") })`. Confetti optional.

### P1-8 — `App.tsx` and `BackgroundAurora` aren't memoised

- **File** : `lock.tsx:185-193` + `App.tsx:41-52` (dead, but for
  completeness)
- **Catégorie** : code-quality, perf
- **Description** : `BackgroundAurora` is a constant component that
  re-renders on every parent render (`LockScreen` re-renders on every
  keystroke into the password field). Wrapping in `React.memo` or
  hoisting outside the component is trivial.

### P1-9 — `dashboard.encrypt.tsx` has empty `catch {}` blocks

- **Files** : `routes/dashboard.encrypt.tsx:32-35` (`/* user
cancelled */`), `dashboard.decrypt.tsx:34-37` (same).
- **Catégorie** : code-quality, comment-as-code-smell
- **Description** : the comment says "user cancelled" but Tauri's
  `open()` returns `null` on cancellation, doesn't throw. The catch
  is for a different exception (the Tauri command not registered in
  dev preview). Comment is misleading. Biome rule
  `noEmptyBlockStatements` is `error` in `biome.json:59` — yet
  `/* user cancelled */` makes the block "non-empty" per Biome's
  parser, which is gaming the rule. Should be `} catch (err) {
console.warn("dialog open failed", err); }` or `if (typeof picked
=== "string")` only without try/catch.

### P1-10 — Test e2e directory is empty (only `__init__.py`) — Playwright spec is a single smoke

- **Files** : `tests/e2e/` (only `__init__.py`),
  `src/guardiabox/ui/tauri/frontend/tests-e2e/smoke.spec.ts` (8 lines,
  just opens `/` and asserts heading).
- **Catégorie** : testing
- **Description** : CLAUDE.md sec 7 mandates "E2E tests (Playwright)
  for critical Tauri flows (encrypt, decrypt, share)". None of the
  three is tested. NFR-9 ("All CI checks ... green for every merge")
  is satisfied trivially — the gate is met because the e2e job
  doesn't fail because there are no real assertions.
- **Recommendation** : write three flows: `encrypt.spec.ts`,
  `decrypt.spec.ts`, `share-accept.spec.ts`. Use `axe-playwright` (in
  deps already, NFR-7 H-13 is open) on each.

### P1-11 — Frontend `Ts.config exactOptionalPropertyTypes` workaround leaks into UI code

- **File** : `routes/dashboard.history.tsx:17-19`,
  `api/client.ts:51-63`
- **Catégorie** : code-quality
- **Description** : the inline comment "exactOptionalPropertyTypes
  rejects { action: undefined }; build the filter object conditionally"
  is repeated in two places. The fix is a tiny utility:

  ```ts
  function dropUndefined<T extends object>(o: T): Partial<T> { ... }
  ```

  …or accept a `omitUndef` builder. Keeping the workaround ad-hoc is
  the third occurrence (Rule of Three). Comment is a CONVENTIONS.md
  sec 10 violation: "comments document _why_, not _what_" — here it
  documents what TS does.

### P1-12 — Inline imports in business logic

- **Files** :
  - `core/operations.py:669` (`import unicodedata` inside
    `_password_bytes`)
  - `sidecar/api/v1/share.py:275-277` (`import time` inside
    `_to_epoch`)
- **Catégorie** : code-quality, style
- **Description** : neither has a circular-import excuse —
  `unicodedata` is stdlib and `time` is already imported at the top
  of share.py's parent modules. Inline imports inside hot paths read
  as "I added this hastily without going to the top".

### P1-13 — `EncryptModal` / `DecryptModal` / `ShareModal` named "Modal" but render as full-page articles

- **Files** : `routes/dashboard.{encrypt,decrypt,share,accept,users,history,settings}.tsx`
- **Catégorie** : naming
- **Description** : every component is named `*Modal` but renders as
  `<article className="mx-auto flex w-full max-w-xl flex-col gap-5
rounded-xl border ...">` inside the dashboard layout's `<main>`
  outlet. They're not modals — they're routed pages. CONVENTIONS.md
  sec 9 expects descriptive PascalCase naming.
- **Recommendation** : rename to `EncryptPage`, `DecryptPage`,
  `SharePage`, etc. ~30 single-symbol find-and-replace.

---

## Findings P2 (nice-to-have)

### P2-1 — `App.tsx` `BackgroundAurora` hard-codes oklch values, not tokens

- **File** : `App.tsx:42-52` (and identical block in `lock.tsx:185-193`)
- **Description** : the gradients use raw `oklch(0.65 0.18 260/0.18)`
  literals. CSS tokens for `--primary` / `--accent` exist already.
  Pure DRY: same 3 background gradients copy-pasted.
- **Fix** : extract to a CSS class `.aurora-background` in `index.css`,
  use `oklch(from var(--primary) ...)`.

### P2-2 — `useDoctor(false, true)` boolean params in `dashboard.settings.tsx:11`

- **Description** : `useDoctor(verifyAudit, reportSsd)` reads
  `useDoctor(false, true)` — mystery booleans at call site,
  CLAUDE.md sec "Boolean params (`do(x, true, false, true)`):
  replace by enum/struct" applies.
- **Fix** : `useDoctor({ reportSsd: true })` with optional named opts.

### P2-3 — `next-themes` loaded but never consumed via `useTheme()`

- **File** : `main.tsx:4` (`import { ThemeProvider } from
"next-themes"`), nothing imports `useTheme`.
- **Description** : alongside P0-3 and the locked dark theme,
  `next-themes` provides zero value. Drop the dep + `<ThemeProvider>`
  if light mode is rejected, or wire a toggle if accepted.

### P2-4 — Stale `biome.json` `files.ignore` reference

- **File** : `biome.json:19` (`"src/components/ui/**"` — that path
  does not exist).
- **Description** : leftover from a planned shadcn `components/ui/`
  layout that never landed. Harmless, but signals "config not
  reviewed".

### P2-5 — `biome.json` rule levels softer than CONVENTIONS.md

- **File** : `biome.json:47-58`
- **Description** : `noUnusedVariables: warn`, `noExplicitAny: warn`,
  `noConsoleLog: warn` — all should be `error` per CONVENTIONS.md
  sec 16 ("Forbidden patterns will block a PR"). CLAUDE.md sec 9bis
  forbids "lowering a quality gate to make CI green".

### P2-6 — `AuditVerifyResponse` and `AuditVerifyView` are duplicate types

- **File** : `api/types.ts:111-115` (`AuditVerifyResponse`) vs
  `232-236` (`AuditVerifyView`)
- **Description** : identical 3-field shape: `ok, first_bad_sequence,
entries_checked`. Pick one name, alias the other.

### P2-7 — `BackgroundAurora` wrapper duplicated between App.tsx and lock.tsx

- **File** : `App.tsx:41-52` (dead) + `lock.tsx:185-193`
- **Description** : same component, two places. Once we delete `App.tsx`
  per P0-1, the duplication disappears. If we want to use the aurora
  on dashboard too (currently only on `/lock`), extract to
  `components/BackgroundAurora.tsx`.

### P2-8 — README claims "Tray + shortcuts" + "Glassmorphism + WebGL" — both unimplemented

- **File** : `README.md:42`
- **Description** : the architecture diagram mentions "Tray +
  shortcuts" (no system tray code in `lib.rs`), "Glassmorphism +
  WebGL" (no Three.js used despite deps). README oversells.
- **Fix** : trim the diagram to what's shipped — frameless
  transparent window + Tauri 2 IPC.

### P2-9 — README binary size claim "≈ 15 MB" but NFR_VERIFICATION says 6.3 MiB shell + 41.7 MiB sidecar + 45.7 MiB NSIS

- **File** : `README.md:36`
- **Description** : "guardiabox.exe (≈ 15 MB, Windows)" doesn't
  match the measured binary sizes (NFR_VERIFICATION.md table).

### P2-10 — Sidecar `app.py` `_DebugLogMiddleware` defined inline before imports

- **File** : `sidecar/app.py:33-73` then `from guardiabox import ...`
  starting line 75
- **Description** : odd ordering — the middleware class is declared
  at module top before the project imports. PEP 8 wants imports first.
  No functional bug, just wrong order.

### P2-11 — Spec naming convention inconsistent ("000-" prefix used for 4 specs, then 001-002-003-004)

- **File** : `docs/specs/`
- **Description** : `000-cli`, `000-multi-user`, `000-tauri-frontend`,
  `000-tauri-sidecar`, `000-tui` then `001-encrypt-file` ... `004-secure-delete`.
  The "000-" prefix usually means "draft" or "meta"; mixing both
  conventions reads as drift.

### P2-12 — "Modal" naming inconsistent with `<article>` element

- See P1-13 above; this is the duplicate at P2 level for completeness.

### P2-13 — `dashboard.tsx:60-72` `navItems` is a literal array constructed inside the component

- **File** : `dashboard.tsx:60-72`
- **Description** : reconstructed on every dashboard render. The icons
  (Lucide React components) are recreated as JSX every render too. Stable
  data — should be a `const` outside the component or inside `useMemo`.

### P2-14 — ADR-0017 is referenced as "candidate" in CHANGELOG but doesn't exist

- **File** : `CHANGELOG.md:80` mentions "ADR-0017 candidate" for
  state management split. `ls docs/adr/` shows 0000-0016 + 0018; no 0017.
- **Description** : "candidate" trailing for 30+ days with the file
  not landing reads as TODO without tracking.

---

## "Premiers 5 minutes UX" — narrative scénario nouvel utilisateur

> **Persona** : a security-aware reviewer (jury Sylvain Labasse, GCS2)
> running `GuardiaBox.exe` for the first time on a fresh Windows 11
> machine. Expectations are calibrated to 1Password / Bitwarden.

**T+0s** — Double-click `GuardiaBox.exe` on the desktop. SmartScreen
warns ("L'ordinateur a été protégé par Windows Defender SmartScreen.
Application non reconnue, éditeur non vérifié — Sacha Marlov"). The
self-signed Authenticode cert (ADR-0018) explains this; the demo
machine is supposed to be pre-prepped, but a non-demo machine eats
this. Reviewer frowns. _Pain point #0_: SmartScreen warning, ADR-0018
documented but visible.

**T+1s** — User clicks "Plus d'infos" → "Exécuter quand même". The
Tauri shell launches. Frameless + transparent window — looks
professional.

**T+1.5s** — But the WebView2 starts blank. Auto-handshake polls every
200 ms (`api/sidecar.ts:23-39`); GUI cold start is **5.7s** per
NFR*VERIFICATION (Phase I metric). For ~5 seconds **the user sees
nothing**. No splash screen, no progress bar, no "Démarrage du
sidecar…". 1Password shows a logo + spinner during boot. \_Pain point
#1*: blank window for 5s.

**T+6s** — The lock screen finally appears. `BackgroundAurora`
gradients, GuardiaBox logo, "Saisissez le mot de passe administrateur
pour déverrouiller le coffre.". This is correct first-run for "vault
not initialised", `useReadyz` returns `vault_initialized: false`, the
"Initialiser un nouveau coffre" button at bottom is shown. **Good.**

**T+8s** — User clicks "Initialiser un nouveau coffre". The form
swaps. Subtitle updates to "Choisissez un mot de passe administrateur
fort. Il ne peut pas être récupéré." — clear copy.

**T+9s** — User types `correct horse battery staple`. The strength
bar shows "█████░░░░░░░░░░░░░░░ Excellent" (because length ≥ 20 and
4 char-classes). _But the label is in French even though the user
hasn't toggled language yet — the label is hard-coded French
(P0-7)._ Reviewer expects a way to change language; the EN/FR toggle
is at top-right, visible but small.

**T+9s** — KDF picker is missing on init. The init form on
`lock.tsx:115-145` only ships `<PasswordField>` + Submit button;
`useInit.mutate({ admin_password: password, kdf: "pbkdf2" })` line 65
hard-codes PBKDF2. The encrypt form has the radio buttons for
PBKDF2 / Argon2id, but the init form doesn't. _Pain point #2_:
academic spec mentions Argon2id as the modern choice, init silently
picks the legacy KDF. Easy fix.

**T+10s** — User hits "Créer le coffre". The button text becomes
"Chargement…" (good, but no spinner). After ~50ms the toast says
"Coffre initialisé. Vous pouvez maintenant le déverrouiller." Form
collapses, returns to the unlock view. **Good.**

**T+11s** — User retypes the same password, clicks "Déverrouiller".
Auth round-trip ~10 ms (KDF in 50 ms-1 s window per NFR-2). Lock
screen disappears, `/dashboard` renders.

**T+12s** — Dashboard view: header with logo + lock button + EN/FR.
Sidebar with 7 nav items: encrypt, decrypt, share, accept, history,
users, settings. Main area shows "Aucun utilisateur" + "Créez votre
premier utilisateur pour commencer." + CTA button. **Empty state is
correct.** Reviewer clicks the CTA.

**T+13s** — `/dashboard/users` page. "Créer un utilisateur" card +
empty list below. Username field + 2 password fields. Reviewer types
`alice` + `correct horse battery staple` + same. Submit. Toast
"Utilisateur alice créé." appears. The list **does not refresh
visually** — the dashboard.users.tsx invalidates `["users"]` via
TanStack Query; refetch triggers but there's no skeleton during the
re-fetch. The list pops in suddenly. _Pain point #3_: no shimmer
loading state.

**T+15s** — Reviewer clicks "Chiffrer un fichier". The encrypt page
loads. Path field + "Choisir…" button + KDF radio + 2 password
fields. _Reviewer drags a file from the desktop onto the window —
**nothing happens** (P0-6). Reviewer clicks "Choisir…", picks a PDF._
Path filled. KDF radio defaults to PBKDF2 (Argon2id is one click
away).

**T+17s** — Reviewer types the password (let's say a different one
than the master, just to see). Hits "Chiffrer". Button shows
"Chargement…". Encryption runs in the sidecar — for a 1 MiB file at
≥100 MiB/s, ~10 ms (NFR-1). Toast appears: "Fichier chiffré : C:\Users\
reviewer\Documents\report.pdf.crypt" then **immediately navigates back
to /dashboard**. _Pain point #4_: the path is a single-line toast
that vanishes in 4 s, and the user is no longer on the encrypt page
— there's no way to copy the output path, no system notification, no
"open folder" CTA.

**T+25s** — Reviewer makes coffee. Returns at T+5min. The auto-lock
default is `auto_lock_minutes` (let's assume 5 min). They type into
the encrypt path field — but the AuthGuard reroutes to `/lock`. _Pain
point #5_: no countdown warning, no "you've been locked due to
inactivity" toast on `/lock` arrival.

**T+5min15s** — Reviewer re-unlocks. Tries the share flow. `/dashboard/
share`. Form has Source / Recipient / Expiration / Output fields.
**The Recipient `<select>` shows just `--`** because Alice is the
only user (P0-8). Form is blocked with no explanation. _Pain point
#6_.

**Net assessment** : the **golden path works** — encrypt and decrypt
with a fresh-init vault end-to-end in ~20s of user time. The
**rough edges** are: no theme toggle, hard-coded FR strength labels,
no drag-drop, no drag-drop hint, no auto-lock countdown, no skeletons,
no system notification on encrypt, no share-flow empty state. **None
is a blocker** for the demo if the demo machine pre-empts them. **All
are visible** to a senior reviewer scanning the UX.

---

## Code metrics estimés

| Metric                                          | Count                                                                           | Status |
| ----------------------------------------------- | ------------------------------------------------------------------------------- | ------ |
| Frontend `.tsx`/`.ts` files > 500 lines         | 0 (largest = `routes/dashboard.share.tsx` at 217)                               | OK     |
| Backend `.py` files > 500 lines                 | 1 (`core/operations.py` at 915)                                                 | DEBT   |
| Functions > 50 lines (visual estimate)          | ~6 (`encrypt_file:99`, `accept_share:120`, `share_file:95`, lock screen render) | DEBT   |
| `# TODO` / `# FIXME` / `# HACK` w/o issue ref   | 0 (only one in a docstring at `state.py:22`)                                    | OK     |
| `# noqa: typing` annotations                    | 0                                                                               | DEBT   |
| Python `Any` usages                             | 16+ (without `# noqa: typing` cover)                                            | DEBT   |
| Python `# type: ignore` markers                 | 9 (across `app.py`, `state.py`, `share.py`)                                     | DEBT   |
| TypeScript `any`                                | 0 (matches biome warn level)                                                    | OK     |
| TypeScript `// @ts-ignore` / `@ts-expect-error` | 0                                                                               | OK     |
| Frontend test files                             | 5 (3 unit + 1 e2e smoke + 1 store)                                              | DEBT   |
| Python test files                               | 44 unit + 17 integration + property + perf                                      | OK     |
| Empty test directories                          | `tests/e2e/` (only `__init__.py`)                                               | DEBT   |
| Dead frontend `.tsx` modules                    | 1 (`App.tsx`)                                                                   | DEBT   |
| Unused dependencies in `package.json`           | ~50 of ~70 declared                                                             | DEBT   |
| Tauri capabilities for unused plugins           | 9 plugin permission groups                                                      | DEBT   |
| `_settings`/`_store` duplicate copies           | 4 (in encrypt/decrypt/vault routers)                                            | DEBT   |
| ADR coverage of architectural decisions         | 16 ADRs accepted + ADR-0017 "candidate" (missing file)                          | OK     |
| `_settings` / `_store` Rule-of-Three breach     | yes (4th occurrence)                                                            | DEBT   |
| React error boundaries                          | 0                                                                               | DEBT   |
| Frontend mutations with skeleton/spinner        | 0 (only button text swap to "Chargement…")                                      | DEBT   |

---

## Conformité CONVENTIONS.md + ADRs (audit scope)

### CONVENTIONS.md sec 2 — DRY (Rule of Three)

**Violated** : `_settings` / `_store` duplicated 4× across sidecar
routers while the canonical `settings_dep` / `store_dep` already
exists in `dependencies.py`. CONVENTIONS.md says "Extract on the
**third** occurrence" — at the 4th, the rule has been openly broken.
See Finding P0-10. Also `encrypt_file`/`encrypt_message`/`share_file`
share KDF + zero-fill ceremony at the 3rd occurrence (P1-2).

### CONVENTIONS.md sec 3 — KISS / economy of abstraction

**Mostly respected.** No premature factory patterns, no Visitor for a
single visit. The `KeyDerivation` Protocol has two implementations
(`Pbkdf2Kdf`, `Argon2idKdf`) — interface justified. **One concern**:
the `_with_derived_key` helper that _should_ exist (per CONVENTIONS.md
sec 2's Rule of Three) is missing — that is YAGNI applied wrongly.

### CONVENTIONS.md sec 4 — YAGNI

**Mostly respected for product features**, **violated for dependencies**.
`docs/specs/` contains a spec for every shipped feature (encrypt,
decrypt, share, secure-delete, multi-user, CLI, TUI, sidecar,
frontend) — strong YAGNI on features. But `package.json` declares
50+ unused deps (see P0-2) — pure "in case we need it later".

### CONVENTIONS.md sec 8 — Type strictness

**Partially violated.** TypeScript: strict mode + every flag enabled,
zero `any` — **excellent**. Python: 16+ `Any` without `# noqa: typing`

- 9 `# type: ignore` — **deviation from sec 4 of CLAUDE.md**.

### CONVENTIONS.md sec 9 — Naming

**Mostly respected** but `*Modal` components that aren't modals
(P1-13) are a clear naming bug. The Python side is exemplary: every
public class is a noun (`Pbkdf2Kdf`, `AesGcmCipher`, `Container`),
every function is a verb (`derive_key`, `encrypt_file`).

### CONVENTIONS.md sec 10 — Comments and docstrings

**Mostly respected.** Default to no comment is honoured in `core/`.
Where comments exist (`operations.py:55-77` module docstring,
`operations.py:198-215` doc on `encrypt_file`), they explain _why_
(NFC normalisation, header AAD construction). **But two
WHAT-not-WHY comments**: `dashboard.history.tsx:17-18` ("filter
object conditionally so the key is absent when no filter set") and
`api/client.ts:51-63` (workaround for `exactOptionalPropertyTypes`)
explain a TS workaround instead of capturing the _why_. P1-11.

### CONVENTIONS.md sec 16 — Forbidden patterns

**Mostly respected.** No `import *`, no `BaseException` catch, no
`assert` outside tests, no `eval`/`exec`. **Soft violation** at
`biome.json` rule levels (P2-5): `noConsoleLog: warn` should be
`error` per the spirit of "Disabling a pre-commit hook to ship faster"
— here we're not disabling, but we're warning where the convention
expects refusal.

### ADR-0011 — Defer cross-platform DB encryption

**Respected.** SQLCipher fallback to column-level AES-GCM is
documented + implemented. `pyproject.toml:73` keeps SQLCipher Linux-
only and the column fallback ships everywhere. The audit log /
filename encryption holds end-to-end.

### ADR-0014 — Chunk-bound AAD

**Respected.** `core/crypto.py::chunk_aad` + `core/operations.py::
_encrypt_stream` lookahead implementation map exactly to ADR
specification. Test coverage in `tests/unit/test_crypto.py` (per
listing).

### ADR-0015 — Anti-oracle stderr unification

**Respected.** `core/operations.py:373-388` (decrypt_file no structlog
warning), `sidecar/api/v1/decrypt.py:135-145` (single
`ANTI_ORACLE_DETAIL`), `sidecar/api/v1/share.py:233-246` (constant
`_ACCEPT_INTEGRITY_DETAIL`), comments cite the ADR. The
`_log.info("sidecar.decrypt.anti_oracle_failure")` event is the
**presence-marker without the discriminator** — ADR-0015 §C is
faithfully implemented.

### ADR-0016 — Tauri↔sidecar IPC security

**Respected at backend level**, **lightly stretched at frontend**:
the loopback bind is enforced (sidecar/main.py); the launch token is
a 32-byte URL-safe random; the auth middleware whitelist is minimal;
session TTL + sliding expiry implemented in
`SessionStore`. **Exception**: ADR-0016 §B mentions "auto-lock
countdown UI" as a frontend deliverable — _the countdown UI does not
render_. P0-5.

### ADR-0017 — frontend state management split

**Missing file.** Referenced as "candidate" in CHANGELOG line 80; no
`docs/adr/0017-*.md` on disk. The split (Jotai + Zustand + TanStack
Query) is implemented and shipped — the ADR documenting it isn't.
P2-14.

### ADR-0018 — Windows Authenticode dev cert

**Respected.** Self-signed cert documented + signing job gated on
`WINDOWS_CERT_PFX_BASE64` secret. The SmartScreen warning is
acknowledged in the doc.

---

## Top 10 quick wins (impact visuel maximal, < 1h chacun)

1. **Delete `App.tsx`** — `git rm` + remove `react-error-boundary`
   un-import (none exists). 30 s of work, removes "bootstrap scaffold"
   smell. (P0-1)

2. **Add drag-drop on encrypt** — `useEffect` subscribing to
   `getCurrentWebview().onDragDropEvent()`, set `path` on drop, toast
   on success. ~25 LoC in `dashboard.encrypt.tsx`. (P0-6)

3. **Wire light-theme toggle** — extend `dashboard.tsx` header with
   a `<ThemeToggle />` calling `useTheme().setTheme`, drop the
   tauri.conf.json hard-coded `"theme": "Dark"`, set `defaultTheme="system"`
   in main.tsx. ~20 LoC. (P0-3)

4. **Add `<AutoLockBadge />` countdown** — read `expiresAtMsAtom`,
   render `mm:ss` in dashboard header, switch to amber under 60 s.
   ~30 LoC. (P0-5)

5. **i18n the password strength labels** — replace
   `LABEL_BY_SCORE` with `t("password.strength.{score}")`, add 5
   keys to `fr.json` + `en.json`. ~15 LoC. (P0-7)

6. **Wrap RouterProvider in `<ErrorBoundary>`** — import
   react-error-boundary (already in deps), render a "Une erreur est
   survenue" card with reload button. ~20 LoC. (P0-4)

7. **Delete `_settings`/`_store` duplicates in 3 routers** — replace
   `Depends(_settings)` with `Depends(settings_dep)` (5 sites total),
   delete the 4 helper functions. ~20 LoC removed. (P0-10)

8. **Add `<Skeleton />` shadcn-style component** — single 10-line
   component, replace the 4 `"Chargement…"` `<p>` with skeleton rows
   in `dashboard.history`, `dashboard.users`, `dashboard.settings`. (P1-6)

9. **Empty-state CTA in share/accept** — `if (otherUsers.length ===
0)` branch, render `<EmptyState />` with `<UserPlus/>` icon and
   `<Link to="/dashboard/users">` CTA. ~20 LoC × 2. (P0-8)

10. **System notification on encrypt success** — `await
isPermissionGranted()`, then `sendNotification({ title, body })`
    on `onSuccess`. ~10 LoC. Already-loaded plugin, zero attack
    surface change. (P1-7)

---

=== AUDIT COMPLETE ===
