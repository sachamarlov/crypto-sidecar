# Audit Frontend (B) -- 2026-04-29

## Executive Summary

Frontend is functionally wired (9 routes, 3 stores, 2 hooks) but **not prod-ready
for soutenance demo**. Three blocking UX defects: (1) the lock screen flips to
"Init vault" by default while `/readyz` is still loading, so a returning user
sees an init CTA on every cold start; (2) every non-422 / non-401 / non-409
sidecar error collapses to a generic "Network error. Is the local sidecar
running?" toast - exactly the "Failed to fetch" symptom the user reported;
(3) `decorations: false` + `transparent: true` ship without a single
`data-tauri-drag-region`, so the window cannot be moved or closed without a
right-click on the taskbar. Capabilities also bundle several `<plugin>:default`
permissions in violation of CLAUDE.md S11 / ADR-0016 sec G. Bundle is bloated
with ~20 unused deps including frontend crypto libs (`@noble/*`,
`argon2-browser`) - a CLAUDE.md S5 anti-pattern.

## Findings P0 (critique, fix avant soutenance)

### P0-1 -- Lock screen defaults to "Init vault" while /readyz is loading

- **File** : `src/guardiabox/ui/tauri/frontend/src/routes/lock.tsx:83,115`
- **Description** : `const isInitialised = readyzQuery.data?.vault_initialized === true;`
  evaluates to `false` while `readyzQuery.data === undefined` (loading) AND
  while `readyzQuery.isError === true` (sidecar handshake not yet complete).
  The render branch then shows the **init vault** form, not the **unlock**
  form, until `/readyz` finally resolves. A returning user with an existing
  vault sees a wrong call to action on every cold start. After the sidecar
  takes ~5.7 s to come up (per `docs/NFR_VERIFICATION.md` NFR-3 DEBT row,
  `NFR_VERIFICATION.md:13`), this means **5+ seconds of misleading UI**.
- **Impact** : Demo regression. Reviewer/jury sees "Initialise the vault"
  during the entire boot animation, then it suddenly flips to "Unlock". Looks
  unfinished, contradicts the lock semantics, and risks the user clicking
  init by accident and triggering a `WeakPasswordError` 400 against an
  already-initialised vault.
- **Fix proposé** :
  ```tsx
  // routes/lock.tsx:83
  if (readyzQuery.isPending) {
    return <BootSplash message={t("lock.booting_sidecar")} />;
  }
  if (readyzQuery.isError) {
    return <SidecarUnreachable error={readyzQuery.error} />;
  }
  const isInitialised = readyzQuery.data.vault_initialized === true;
  ```
  Add `lock.booting_sidecar` and `lock.sidecar_unreachable` keys to
  `src/i18n/{fr,en}.json`. The `BootSplash` should use the existing
  `BackgroundAurora` + a `Loader2` spinner with `aria-live="polite"` so SR
  users are notified.

### P0-2 -- Generic "Failed to fetch" / errors.network toast hides every diagnostic

- **File** :
  - `src/guardiabox/ui/tauri/frontend/src/routes/lock.tsx:55`
  - `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.encrypt.tsx:60`
  - `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.decrypt.tsx:59`
  - `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.share.tsx:88`
  - `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.accept.tsx:81`
  - `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.users.tsx:45,56`
  - `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.history.tsx:32`
- **Description** : Every `else` branch in every `onError` callback calls
  `toast.error(t("errors.network"))`. The fr/en translations are
  `"Erreur reseau. Le sidecar local est-il demarre ?"` /
  `"Network error. Is the local sidecar running?"` (`fr.json:147`,
  `en.json:147`). This is dispatched for **every** non-`SidecarHttpError`
  rejection: `TypeError: Failed to fetch` (CORS preflight failure, sidecar
  not yet ready, port closed), the `getSidecarConnection` 10-s handshake
  timeout, **and** any unexpected runtime error. The user can't tell:
  - sidecar still booting (wait)
  - sidecar crashed (read logs)
  - CORS misconfig (regression)
  - network blocked by AV (whitelist)
  - bug in the frontend itself
    This is exactly what made the user lose ~30 minutes today on the CORS /
    middleware-order / PyInstaller noconsole bugs.
- **Impact** : No diagnostic surface. Every regression in the IPC layer
  produces the same opaque toast. Soutenance jury cannot understand why the
  demo failed if anything goes wrong.
- **Fix proposé** : Branch on the underlying error class **inside**
  `api/client.ts` and dispatch a typed error. Three concrete branches:
  ```ts
  // api/client.ts (new):
  export class SidecarUnreachableError extends Error {
    constructor(public readonly stage: "handshake" | "fetch" | "timeout") {
      super(`sidecar unreachable at stage=${stage}`);
    }
  }
  // sidecar.ts: throw SidecarUnreachableError("handshake") instead of
  //   `new Error("sidecar handshake did not complete within 10s")`.
  // client.ts: catch TypeError from fetch() and rethrow as
  //   SidecarUnreachableError("fetch"). Catch AbortError as ("timeout").
  ```
  Then add `errors.sidecar_unreachable.{handshake,fetch,timeout}` keys with
  actionable copy:
  - handshake : "Le sidecar local n'a pas répondu en 10 s. Redémarrez
    GuardiaBox ou consultez `%TEMP%/guardiabox-sidecar.log`."
  - fetch : "Connexion au sidecar perdue. Le processus a-t-il été tué ?
    Vérifiez votre antivirus."
  - timeout : "La requête a expiré. Le sidecar est peut-être occupé
    (chiffrement en cours)."

### P0-3 -- Frameless transparent window has no drag region, cannot be moved or closed

- **File** : `src/guardiabox/ui/tauri/src-tauri/tauri.conf.json:23-24` +
  `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.tsx:76` +
  `src/guardiabox/ui/tauri/frontend/src/routes/lock.tsx:86`
- **Description** : `tauri.conf.json` sets `"decorations": false,
"transparent": true`. The capabilities allow `core:window:allow-start-dragging`
  (`capabilities/default.json:11`) but no element in the React tree carries
  `data-tauri-drag-region`. Result: there is no native title bar and no
  custom drag surface. The user **cannot move the window** anywhere on
  screen without right-clicking the taskbar entry. Worse, no close /
  minimize / maximize buttons exist either - the user must Alt+F4 or close
  via the taskbar.
- **Impact** : First-launch UX is broken. The window appears centered
  (`"center": true`) but cannot be repositioned to e.g. side-by-side with the
  CLI demo terminal. On a multi-monitor demo machine this is a hard block.
  Reviewer experience suffers immediately.
- **Fix proposé** : Add a custom title bar to `routes/dashboard.tsx` and
  `routes/lock.tsx` headers:
  ```tsx
  // routes/dashboard.tsx: replace existing <header ...> opening tag
  <header
    data-tauri-drag-region
    className="flex items-center justify-between border-border border-b bg-card/40 px-6 py-3 backdrop-blur-sm"
  >
    {/* drag region attaches to the header div; child buttons opt out */}
    <div className="pointer-events-none flex items-center gap-2"
         data-tauri-drag-region>
      <LockKeyhole ... />
      <span ...>{t("app.name")}</span>
    </div>
    <div className="pointer-events-auto flex items-center gap-2">
      {/* buttons here, NOT drag-region */}
      <WindowControls />  {/* close / min / max */}
    </div>
  </header>
  ```
  Similar treatment on `lock.tsx:86`. Add a `<WindowControls />` component
  using `getCurrentWindow()` from `@tauri-apps/api/window` with `close`,
  `minimize`, `toggleMaximize` calls.

### P0-4 -- Capabilities bundle :default permissions in violation of CLAUDE.md S11 + ADR-0016 sec G

- **File** : `src/guardiabox/ui/tauri/src-tauri/capabilities/default.json:7-21,27-38`
- **Description** : The file's own `description` field claims "Permissions
  are listed individually rather than via plugin bundles so the attack
  surface is auditable" and "never widen blindly with `<plugin>:default`".
  Yet 12 `:default` bundle entries are present:
  - `core:default`, `core:webview:default`, `core:event:default`,
    `core:image:default`, `core:menu:default`, `core:tray:default`,
    `core:resources:default`, `core:path:default`
  - `fs:default` (broad filesystem - no scope restriction to vault root)
  - `notification:default` (then duplicated by `notification:allow-notify`)
  - `store:default`, `window-state:default`
    CLAUDE.md S11 explicitly forbids: "Replacing granular Tauri capabilities
    with `<plugin>:default` bundles to make build pass". This is the exact
    pattern shipped here.
- **Impact** : Direct violation of an ADR-anchored rule. Easy reviewer
  catch. `fs:default` is the worst offender - it grants every fs verb
  without any `scope` clause restricting reads/writes to the vault data
  directory. A compromised renderer can `readFile`/`writeFile`/`removeFile`
  anywhere in the user's home dir. Defence-in-depth lost.
- **Fix proposé** : Replace each `:default` with the explicit list of
  allowed verbs. For `fs`, add a `scope` clause. Example:

  ```json
  {
    "permissions": [
      // Drop "core:default", inline only what is used:
      "core:app:allow-version",
      "core:event:allow-listen",
      "core:event:allow-emit",
      "core:path:allow-resolve-directory",
      // ... etc

      // Drop "fs:default", restrict to data dir + dialog-picked paths:
      "fs:allow-read-file",
      "fs:allow-write-file",
      {
        "identifier": "fs:scope",
        "allow": [
          { "path": "$APPDATA/guardiabox/**" },
          { "path": "$HOME/Documents/**" } // dialog-picked encrypts
        ]
      },

      // Drop "notification:default" duplicated with allow-notify:
      "notification:allow-notify"
    ]
  }
  ```

  Verify against actual feature usage by running `tauri dev` and watching
  for `[ERROR] permission missing: ...` in the console - then add only those.

### P0-5 -- Vault-locked dashboard query mounts before navigation, leaking 401s

- **File** : `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.tsx:44-46,30`
- **Description** : `DashboardChrome()` is rendered as a child of
  `<AuthGuard>`, but `useUsers()` and `useAutoLock()` (and any nested
  query) execute on first render even if the AuthGuard is **about to**
  redirect. Since `AuthGuard` evaluates `isUnlockedAtom` every render,
  during the brief window between session-expiry and the AuthGuard's
  re-render, `useUsers()` may fire a request that lands as a 401 on the
  server (the session is gone) - which the frontend doesn't handle, so it
  falls through to `errors.network`.
- **Impact** : Spurious "Network error" toast on auto-lock. Confusing.
- **Fix proposé** : Guard the chrome query firing on `isUnlockedAtom`:
  ```tsx
  const usersQuery = useUsers({ enabled: useAtomValue(isUnlockedAtom) });
  ```
  Plus add a 401 branch in `api/queries.ts useUsers` `onError` to redirect
  to `/lock` cleanly, or return a typed error that the chrome surfaces as
  "Session expired" instead of "Network error".

### P0-6 -- Lock screen submits empty password against init endpoint with no zxcvbn confirmation

- **File** : `src/guardiabox/ui/tauri/frontend/src/routes/lock.tsx:115-146`
- **Description** : The init form has **one** password field, **no
  confirmation field**, and the `disabled` predicate is only
  `password.length < 12`. A user types a typo, submits, and the vault is
  initialised with a password they cannot reproduce. The encrypt/users
  flows have a confirm field (`encrypt.tsx:117,users.tsx:82`) but init -
  the **most critical** password input in the entire app - does not. Plus
  there is no explicit acknowledgement that "this password cannot be
  recovered" - just a small subtitle (`lock.init_subtitle`).
- **Impact** : Permanent vault lockout if the user mistypes. This is
  catastrophic for an academic demo.
- **Fix proposé** :
  ```tsx
  // lock.tsx, init branch:
  const [confirm, setConfirm] = useState("");
  const [acknowledged, setAcknowledged] = useState(false);
  // ...
  <PasswordField value={password} onChange={setPassword} />
  <PasswordField value={confirm} onChange={setConfirm}
                 placeholder={t("password.confirm_placeholder")}
                 showStrength={false} />
  <label className="flex items-start gap-2 text-xs">
    <input type="checkbox" checked={acknowledged}
           onChange={(e) => setAcknowledged(e.target.checked)} />
    <span>{t("lock.init_acknowledgement")}</span>
  </label>
  <button disabled={
    initMutation.isPending ||
    password.length < 12 ||
    password !== confirm ||
    !acknowledged
  } ...>
  ```
  New i18n key: `lock.init_acknowledgement`: "Je comprends que ce mot de
  passe est irrécupérable. La perte du mot de passe entraîne la perte
  définitive du coffre."

### P0-7 -- Decrypt anti-oracle leaks via fallthrough on non-422 SidecarHttpError

- **File** : `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.decrypt.tsx:54-58`
- **Description** : The decrypt `onError` is anti-oracle-correct for 422
  (constant `decrypt.anti_oracle_failure` toast). But the `else if (err
instanceof SidecarHttpError)` branch on line 56 forwards `err.detail`
  verbatim. Per ADR-0015 / ADR-0016 sec C, **post-KDF** failures collapse
  to 422; **pre-KDF** failures (InvalidContainer, UnsupportedVersion,
  UnknownKdf, WeakKdfParameters, CorruptedContainer) keep their distinct
  4xx codes (typically 400 or 409). That is by design - they don't leak
  about the password. **However**, the strings carried in `err.detail`
  are server-controlled and likely not localised (e.g. the FastAPI
  default `"unknown kdf"`, `"weak kdf parameters: m_cost=1"` etc.). The
  toast surfaces these untranslated, breaking NFR-6 (FR + EN coverage).
- **Impact** : i18n hole (low) + UX inconsistency. Anti-oracle invariant
  is preserved, so this is not a security finding - rated P0 only because
  it surfaces during a demo flow that touches a malformed `.crypt`.
- **Fix proposé** :
  ```tsx
  } else if (err instanceof SidecarHttpError) {
    // Pre-KDF parse failures - distinct from 422 anti-oracle toast.
    // Translate by status, not by server detail.
    if (err.status === 400) toast.error(t("decrypt.invalid_container"));
    else if (err.status === 409) toast.error(t("decrypt.unsupported_version"));
    else toast.error(t("decrypt.unknown_error"));
  }
  ```
  Add the 3 keys to fr/en. Document this branching in the comment block at
  line 50.

## Findings P1

### P1-1 -- No React error boundary, despite `react-error-boundary` being a dep

- **File** : `src/guardiabox/ui/tauri/frontend/src/main.tsx:42-52` +
  `src/guardiabox/ui/tauri/frontend/src/routes/__root.tsx:8-15` +
  `package.json:90`
- **Description** : `react-error-boundary` is in `dependencies` but never
  imported. A render-time exception in any route component propagates up
  to React, which renders nothing - the user sees a blank window. The
  React 19 + StrictMode default error display only shows in DEV.
- **Impact** : Any uncaught render error in prod = blank window. No
  recovery path.
- **Fix proposé** : Wrap `<Outlet />` in `routes/__root.tsx` with
  `<ErrorBoundary fallbackRender={ErrorFallback}>` and define a route-level
  `ErrorFallback` showing the error message + a "Reload" button calling
  `window.location.reload()`. Plus a "Lock vault" CTA that resets the
  Jotai atoms. TanStack Router also supports `errorComponent` per route -
  use it on `__root` for the safety net.

### P1-2 -- TanStack Query default `retry: 1` masks transient sidecar errors with double-latency

- **File** : `src/guardiabox/ui/tauri/frontend/src/main.tsx:20`
- **Description** : `defaultOptions.queries.retry: 1` means every failed
  query retries once. On the lock screen, `useReadyz` polls `/readyz`; if
  the sidecar is still spawning, the first call gets `TypeError: Failed to
fetch`, retries 1s later, then surfaces the error to the UI. With the
  10 s handshake timeout in `getSidecarConnection`, the actual time-to-
  visible-error can be 20+ seconds. Plus mutations (`useUnlock`) inherit
  retries on 5xx (not by default for mutations, but worth checking) which
  is dangerous on rate-limited endpoints (`/vault/unlock` is 5/min - any
  retry burns the budget).
- **Impact** : Slow boot. Possible rate-limit consumption on auth
  endpoints if the user double-clicks.
- **Fix proposé** :
  ```ts
  // main.tsx
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      refetchOnWindowFocus: false,
      retry: (failureCount, error) => {
        // Retry up to 3x on sidecar boot (TypeError: Failed to fetch)
        if (error instanceof TypeError) return failureCount < 3;
        // Don't retry on app-level 4xx
        if (error instanceof SidecarHttpError && error.status < 500) return false;
        return failureCount < 1;
      },
      retryDelay: (attempt) => Math.min(1000 * 2 ** attempt, 5000),
    },
    mutations: { retry: false },  // explicit, never retry mutations
  },
  ```

### P1-3 -- Auto-lock countdown is invisible to the user

- **File** : `src/guardiabox/ui/tauri/frontend/src/hooks/useAutoLock.ts:1-37`
- **Description** : `useAutoLock` ticks every 1 s but never exposes the
  remaining time. `dashboard.tsx` has a "Lock now" button but no countdown
  display. The user has no idea whether they have 12 minutes or 12 seconds
  before the next request silently 401s.
- **Impact** : Surprising auto-lock during typing. UX trust loss.
- **Fix proposé** : Surface the remaining time in the dashboard header.
  Add a `useTimeRemaining()` hook ticking at 1 Hz and display
  `⏱ 14:23` next to the "Lock now" button. Bonus: when remaining < 60 s,
  flash an `<motion.span aria-live="polite">` announcing "Auto-lock
  imminent" so SR users know.

### P1-4 -- Sliding TTL not implemented despite ADR-0016 sec B promising it

- **File** : `src/guardiabox/ui/tauri/frontend/src/hooks/useAutoLock.ts:1-37`
  - `src/guardiabox/ui/tauri/frontend/src/api/client.ts:39-78`
- **Description** : ADR-0016 sec B states "TTL = `auto_lock_minutes` ...
  reaper task zero-fills on expiry" - implying the server slides the TTL
  on each authenticated request. The frontend stores
  `expires_in_seconds` once at unlock (`lock.tsx:47`) and never refreshes
  it. So if the server is also static-TTL (likely - I didn't read the
  reaper), the user gets logged out exactly N minutes after unlock,
  regardless of activity. If the server IS sliding, the frontend's
  countdown lies.
- **Impact** : Disagreement between client and server clocks. Edge case
  but visible to power users.
- **Fix proposé** : Either (a) confirm the server resets the TTL on every
  authenticated request and update `expiresAtMsAtom` to slide on the
  client side too (track last activity timestamp from `usePrevious` /
  fetch interceptor), or (b) confirm the server uses a hard TTL and
  document it in the i18n hint near the "Lock now" button. Read the
  sidecar `state.py` reaper to decide.

### P1-5 -- TanStack Query data invalidation doesn't reset on lock

- **File** : `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.tsx:48-55`
  - `src/guardiabox/ui/tauri/frontend/src/hooks/useAutoLock.ts:24-33`
- **Description** : When the user locks the vault, `setSessionId(null)` +
  `setExpiresAt(null)` are called, but the React Query cache is **not**
  cleared. If the same user immediately unlocks again, stale data from
  the previous session (including potentially a different active user
  picker, audit entries from a previously selected user) is shown until
  the network refetch resolves. Worse: if a different OS user logs in
  and uses the same Tauri window (rare but possible in shared lab demos),
  they see the previous session's user list during the boot flicker.
- **Impact** : Cross-session leak of cached metadata. Low security
  impact (users list is metadata, not crypto material) but a privacy
  smell. UX flicker is annoying.
- **Fix proposé** :
  ```tsx
  // dashboard.tsx: onLock
  const queryClient = useQueryClient();
  const onLock = (): void => {
    if (sessionId !== null) lockMutation.mutate({ session_id: sessionId });
    setSessionId(null);
    setExpiresAt(null);
    queryClient.clear(); // drop all cached queries
    void navigate({ to: "/lock" });
  };
  ```
  Same in `useAutoLock`.

### P1-6 -- `routes/dashboard.tsx` users.create on lock-button-click ignores network race

- **File** : `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.tsx:48-55`
- **Description** : `onLock` calls `lockMutation.mutate(...)` and then
  immediately `setSessionId(null)`. The `mutate` call uses the session
  header from `getDefaultStore().get(sessionIdAtom)` (`api/client.ts:47`).
  Because Jotai writes are synchronous but the `fetch` is async, the
  request actually fires with the stale session id (correct) but if the
  user hammers "Lock" then "Unlock" in <100 ms, the lock POST may arrive
  AFTER the unlock POST has already established a new session - and the
  server's lock handler may invalidate the new session. Race condition.
- **Impact** : Edge case. Hard to reproduce but real.
- **Fix proposé** : `await` the mutation before clearing the local state:
  ```tsx
  const onLock = async (): Promise<void> => {
    if (sessionId !== null) {
      await lockMutation.mutateAsync({ session_id: sessionId });
    }
    setSessionId(null);
    setExpiresAt(null);
    void navigate({ to: "/lock" });
  };
  ```

### P1-7 -- `dashboard.users.tsx` uses `window.confirm` instead of an accessible dialog

- **File** : `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.users.tsx:53`
- **Description** : `window.confirm(t("users.delete_confirm_subtitle"))` is
  the only confirmation step before destroying a user (and their RSA
  keystore + vault key + already-shared `.gbox-share` tokens become
  unreadable per the message). `window.confirm`:
  - has no theming - shows a Win11/macOS native dialog mid-app
  - has no `role="alertdialog"` semantics for SR
  - cannot be styled to match destructive red CTA
  - blocks the entire page (synchronous)
  - i18n string is hard to read in a small native dialog
- **Impact** : Theme break + a11y failure on a destructive action.
- **Fix proposé** : Use Radix `<AlertDialog>` (already a dep -
  `@radix-ui/react-alert-dialog`). Define `<ConfirmDestructive title=...
body=... confirmLabel=... onConfirm=... />` as a reusable component.

### P1-8 -- `dashboard.share.tsx` recipientId picker shows raw user_ids when usernames missing

- **File** : `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.share.tsx:127-141`
- **Description** : `<select>` lists `otherUsers.map(u => <option
value={u.user_id}>{u.username}</option>)`. If `usersQuery` is still
  loading or the list is empty, only the disabled `--` option shows.
  No empty-state message ("No other users yet - create one in
  /dashboard/users"). The disabled-state submit button has the right
  predicate (`recipientId.length === 0`) so the user can't submit, but
  there is no guidance about what to do next.
- **Impact** : Dead-end UX.
- **Fix proposé** : Conditional render:
  ```tsx
  {usersQuery.isLoading ? (
    <p>{t("common.loading")}</p>
  ) : otherUsers.length === 0 ? (
    <p className="text-amber-300/80">
      {t("share.no_other_users")}{" "}
      <Link to="/dashboard/users" className="underline">
        {t("dashboard.actions.users")}
      </Link>
    </p>
  ) : (
    <select ...>...</select>
  )}
  ```

### P1-9 -- Fingerprint warning on share is text-only - no actual fingerprint shown

- **File** : `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.share.tsx:188-192`
- **Description** : The "Step 2 - Confirmation" branch shows a generic
  warning telling the user to "verify the fingerprint out-of-band" but
  **never displays an actual fingerprint to verify**. The TUI / CLI
  share flow renders the recipient's RSA-public-key SHA-256 hex
  fingerprint (cf. spec 003-rsa-share). This UI version skips that step
  entirely. Without a fingerprint shown, the warning is empty theatre.
- **Impact** : Per `docs/THREAT_MODEL.md` and ADR-0004 (RSA-OAEP-4096
  hybrid sharing), the OOB fingerprint check is the **only** mitigation
  against a local user-DB compromise injecting a substituted recipient
  public key. Removing the fingerprint display kills that mitigation in
  the GUI flow.
- **Fix proposé** : Read the recipient's fingerprint via a new
  `GET /api/v1/users/{id}/fingerprint` endpoint, or extend `UserView`
  with `rsa_public_fingerprint: string`. Display in the confirm step:
  ```tsx
  <div className="rounded-md border border-amber-500/40 p-3">
    <p className="text-xs">{t("share.fingerprint_warning")}</p>
    <code className="mt-2 block break-all font-mono text-sm">
      {recipientFingerprint}
    </code>
    <p className="mt-2 text-xs">{t("share.fingerprint_oob_hint")}</p>
  </div>
  ```

### P1-10 -- TypeScript `paths` alias is not declared in `tsconfig.node.json` for Vite config

- **File** : `src/guardiabox/ui/tauri/frontend/vite.config.ts:1-7` +
  `src/guardiabox/ui/tauri/frontend/tsconfig.node.json` (referenced via
  `tsconfig.json:48`)
- **Description** : `vite.config.ts` imports `path` from `node:path`
  and uses `__dirname`. The references project structure puts the Vite
  config under `tsconfig.node.json`. If that file does not include
  `node` types, building under `tsc -b` may produce missing-type
  diagnostics. Could not verify without reading `tsconfig.node.json`,
  but it's a low-risk audit hint. (`pnpm build` ran green per
  `922115c` commit so likely OK.)
- **Impact** : Build-time only; low.
- **Fix proposé** : Verify `tsconfig.node.json` declares
  `"types": ["node"]`. If pnpm build is currently green, no action.

## Findings P2

### P2-1 -- Massive unused dependencies inflating bundle

- **File** : `src/guardiabox/ui/tauri/frontend/package.json`
- **Description** : Imported nowhere in `src/`:
  - `argon2-browser` (`package.json:74`) - **frontend crypto dep**
  - `@noble/ciphers` (`package.json:31`) - **frontend crypto dep**
  - `@noble/hashes` (`package.json:32`) - **frontend crypto dep**
  - `three`, `@react-three/fiber`, `@react-three/drei`,
    `@react-three/postprocessing` (~3-5 MiB minified each)
  - `@radix-ui/*` × 22 packages - none currently imported
  - `cmdk`, `react-hotkeys-hook`, `@tauri-apps/plugin-global-shortcut`
    (cmd-K command palette is "out of scope" per spec)
  - `canvas-confetti`, `lenis`, `vaul`, `immer`,
    `react-resizable-panels`
  - `react-hook-form`, `@hookform/resolvers`, `zod` (forms use raw
    `useState` + `FormEvent`)
  - `storybook` is in `devDependencies` but no `.storybook/` config
- **Impact** :
  1. **Security smell (CLAUDE.md S5)**: `argon2-browser` + `@noble/*`
     declare crypto in the UI dep tree. CLAUDE.md S5 says "Never
     reimplement crypto in UI layers". An AI coding agent or a
     maintainer who imports them by reflex breaks the architecture
     invariant. They should be removed from `dependencies` entirely.
  2. **Bundle weight**: even with manualChunks splitting
     (`vite.config.ts:48-58`), Vite tree-shakes only what's imported,
     so unused deps are mostly dead. But pnpm install / lockfile size
     / supply-chain audit surface are unnecessarily large.
  3. **CDC compliance**: Bandit / pip-audit / npm-audit have to scan
     all of them. Dead deps are pure exposure.
- **Fix proposé** :
  ```bash
  pnpm --dir src/guardiabox/ui/tauri/frontend remove \
    argon2-browser @noble/ciphers @noble/hashes \
    three @react-three/fiber @react-three/drei @react-three/postprocessing \
    @radix-ui/react-accordion @radix-ui/react-alert-dialog \
    @radix-ui/react-avatar @radix-ui/react-checkbox \
    @radix-ui/react-context-menu @radix-ui/react-dialog \
    @radix-ui/react-dropdown-menu @radix-ui/react-hover-card \
    @radix-ui/react-popover @radix-ui/react-progress \
    @radix-ui/react-radio-group @radix-ui/react-scroll-area \
    @radix-ui/react-select @radix-ui/react-separator \
    @radix-ui/react-slider @radix-ui/react-slot @radix-ui/react-switch \
    @radix-ui/react-tabs @radix-ui/react-toast @radix-ui/react-tooltip \
    cmdk react-hotkeys-hook canvas-confetti lenis vaul immer \
    react-resizable-panels react-hook-form @hookform/resolvers zod \
    storybook
  ```
  Add `@radix-ui/react-alert-dialog` back if implementing P1-7.
  Keep `react-hook-form` + `zod` if planning to refactor forms (current
  raw `useState` is borderline acceptable for these simple flows).
  Remove `@tauri-apps/plugin-global-shortcut` from `package.json` AND
  the corresponding `global-shortcut:*` permissions from
  `capabilities/default.json:39-41` to keep them in sync.

### P2-2 -- `App.tsx` is dead code never imported

- **File** : `src/guardiabox/ui/tauri/frontend/src/App.tsx:1-52`
- **Description** : Greppable: no file imports `App`. The router takes
  over from `main.tsx` directly. This file was the bootstrap placeholder
  and survived commit ce8734f.
- **Impact** : Dead code, drift risk, confuses readers ("which entry
  point is real?").
- **Fix proposé** : `rm src/App.tsx`.

### P2-3 -- Duplicated language-toggle code in `lock.tsx` + `dashboard.tsx`

- **File** : `src/guardiabox/ui/tauri/frontend/src/routes/lock.tsx:88-97`
  - `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.tsx:87-94`
- **Description** : Identical `<button>` rebuilding language toggle
  twice. Per CLAUDE.md S4 "Rule of Three" we are at 2 copies; if a
  third lands (e.g., onboarding flow), extract to `<LanguageToggle />`
  in `src/components/`. Worth doing now since the strings are i18n keys
  that should be centralised, and the toggle is an a11y touch point
  (must be keyboard reachable in tab order).
- **Impact** : Drift risk; a11y polish opportunity.
- **Fix proposé** : Extract to `src/components/LanguageToggle.tsx`:
  ```tsx
  export function LanguageToggle(): React.ReactElement {
    const { t } = useTranslation();
    const language = useLanguageStore((s) => s.language);
    const setLanguage = useLanguageStore((s) => s.setLanguage);
    return (
      <button
        type="button"
        onClick={() => setLanguage(language === "fr" ? "en" : "fr")}
        className="..."
        aria-label={t("common.language")}
        title={language === "fr" ? "Switch to English" : "Basculer en français"}
      >
        {language === "fr" ? "EN" : "FR"}
      </button>
    );
  }
  ```

### P2-4 -- Misleading docstring in `stores/lock.ts:32` references nonexistent endpoint

- **File** : `src/guardiabox/ui/tauri/frontend/src/stores/lock.ts:32`
- **Description** : `/** Active user id (after `/users/{id}/unlock` --
per-user vault key). */` - but `/users/{id}/unlock` does NOT exist in
  the sidecar (greppable: only `/api/v1/vault/unlock` exists in
  `sidecar/api/v1/vault.py:96`). The comment is documentation debt
  inherited from ADR-0016 sec B's per-user session sketch that was
  partially deferred.
- **Impact** : Low. Misleads agents reading the code.
- **Fix proposé** : Correct the comment:
  ```ts
  /**
   * Active user id - tracks which vault user the share/accept flows
   * should target. Set client-side from `dashboard.index.tsx` button.
   * Per-user RSA-private unwrap happens on the server during share/
   * accept (see ADR-0004); the frontend never holds a per-user key.
   */
  export const activeUserIdAtom = atom<string | null>(null);
  ```

### P2-5 -- No `force` toggle in encrypt / share / accept UIs despite types declaring it

- **File** : `src/guardiabox/ui/tauri/frontend/src/api/types.ts:127,164,179`
  - `src/guardiabox/ui/tauri/frontend/src/routes/dashboard.{encrypt,share,accept}.tsx`
- **Description** : `EncryptRequest`, `ShareRequest`, `AcceptRequest` all
  declare an optional `force?: boolean` (overwrite existing output).
  None of the three forms expose a checkbox. If the user re-encrypts a
  file or re-shares, the server returns 409 (likely "output exists") and
  the frontend surfaces it via `err.detail` as untranslated text.
- **Impact** : Power users blocked. Demo flow stutters if the path is
  re-typed.
- **Fix proposé** : Add a "force overwrite" checkbox below each
  output-path field, gated to only show after the user attempts a
  submission and gets a 409. Add i18n keys
  `{encrypt,share,accept}.force_overwrite_label` and
  `errors.output_exists`.

### P2-6 -- WCAG 2.2 AA: focus rings are conditional on `:focus-visible` only - missing on programmatic focus

- **File** : Multiple — search for `focus-visible:` shows the rings only
  on `:focus-visible`. Per WCAG 2.4.7, focus indicator must be visible
  on **any** focus, not only when keyboard navigation triggered it. With
  `:focus-visible` only, programmatically-focused elements (e.g.
  `autoFocus={true}` on `PasswordField`) get no ring.
- **Impact** : WCAG 2.4.7 fail in some browsers' interpretations.
- **Fix proposé** : Either keep the `:focus-visible` behaviour (which is
  the modern, browser-validated heuristic) and add a separate
  `:focus:ring-1 ring-ring/50` for programmatic focus, or accept the
  WAI-ARIA Authoring Practices guidance that `:focus-visible` is
  sufficient for keyboard users. Document in spec the chosen
  interpretation. axe-playwright disagrees with neither.

### P2-7 -- Vitest coverage is far below the spec target (NFR-8 ≥ 80 % global, ≥ 95 % api/hooks)

- **File** : test files are 3 (`PasswordField.test.tsx`, `password.test.ts`,
  `lock.test.ts`) covering ~3 modules out of ~25.
- **Description** : NFR-8 mandates ≥ 80 % global, ≥ 95 % on `api/` and
  `hooks/`. Today: zero tests on `api/client.ts`, `api/queries.ts`,
  `api/sidecar.ts`, `hooks/useAutoLock.ts`. Estimated coverage <30 %.
  The CI gate is gated on H-17 (per `tasks.md:48-49,60`) which is still
  marked partial.
- **Impact** : Regression risk. Hard to spot a `client.ts` interceptor
  break (the kind that produced today's CORS regression).
- **Fix proposé** : At minimum write:
  - `api/client.test.ts`: mocked fetch, asserts headers
    (`X-GuardiaBox-Token` + `X-GuardiaBox-Session`), 204 → undefined,
    non-OK → `SidecarHttpError`, body JSON parse failure fallthrough.
  - `hooks/useAutoLock.test.tsx`: vitest `useFakeTimers`, advance
    time, assert `setSessionId(null)` + lock POST.
  - `api/sidecar.test.ts`: mock `invoke`, polling loop, timeout path,
    cache reset.
    Activate the CI frontend job once these land.

### P2-8 -- TanStack Query `staleTime` 30s on `/readyz` blinds the UI to sidecar restart

- **File** : `src/guardiabox/ui/tauri/frontend/src/api/queries.ts:53`
  - `src/guardiabox/ui/tauri/frontend/src/main.tsx:18`
- **Description** : `useReadyz` overrides `staleTime: 10_000`, so the
  UI considers `/readyz` "fresh" for 10 s. If the sidecar crashes and
  is auto-respawned within that window (uncommon but plausible during
  development), the UI does not refetch and may render stale state.
  Same concern with `useVaultStatus` (5 s). Acceptable defaults but
  worth documenting.
- **Impact** : Low. Edge case during dev.
- **Fix proposé** : Document the staleness windows in a comment near
  the queries. Or: set `refetchOnReconnect: true` on `useReadyz` so a
  network blip triggers a refetch.

## Conformité ADR (TON périmètre)

| ADR                                           | Statut                                                                                                                                                                                                                                                             |
| --------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **ADR-0001** (Tauri 2 + Python sidecar)       | **Respecté.** WebView2, sidecar via externalBin, loopback HTTP per-launch token, handshake parser strict (`sidecar.rs:205-225`).                                                                                                                                   |
| **ADR-0005** (Vite over Next.js)              | **Respecté.** Pure SPA, Vite 7, no SSR.                                                                                                                                                                                                                            |
| **ADR-0011** (cross-platform DB encryption)   | **Respecté côté frontend** — la couche admin password unlock (`useUnlock`) cible bien le vault admin password qui dérive la clé d'encryption au niveau colonne; pas de mention de SQLCipher dans le frontend (correct).                                            |
| **ADR-0015** (anti-oracle stderr unification) | **Partiellement respecté.** Le toast `decrypt.anti_oracle_failure` est constant côté UI, mais le branch P0-7 forwards `err.detail` verbatim sur les statuts non-422, ce qui peut leak des messages serveur non-i18n. À durcir.                                     |
| **ADR-0016** (Tauri sidecar IPC)              | **Partiellement respecté.** Token + session headers OK (`client.ts:42-50`). Anti-oracle 422 OK. **Sec G violé** par les `:default` bundles dans `capabilities/default.json` (cf. P0-4). Sec C OK pour 422 mais les autres status ne propagent pas la localisation. |
| **ADR-0017**                                  | **N'existe pas dans `docs/adr/`.** Le brief mentionne "ADR-0017?" et le frontend `tasks.md:62` parle d'"ADR-0017 candidate" pour le state-management split — cette ADR n'a jamais été écrite. Doc debt à signaler.                                                 |
| **ADR-0018** (Authenticode dev cert)          | **Hors périmètre frontend** mais conforme côté `tauri.conf.json` (NSIS + MSI bundle ciblés `bundle.targets:37`). Pas de problème observable.                                                                                                                       |
| **ADR-0004** (RSA-OAEP-4096 hybrid sharing)   | **Partiellement respecté.** Le flux share existe mais sans afficher la vraie fingerprint OOB (cf. P1-9). Le warning text n'a pas de fingerprint à vérifier — la mitigation est neutralisée.                                                                        |

## UX critique : "Failed to fetch" et autres messages génériques

Liste exhaustive des fallthrough produisant un toast non-actionnable :

| File:Line                          | Toast                                       | Vrai cause possible                                  |
| ---------------------------------- | ------------------------------------------- | ---------------------------------------------------- |
| `routes/lock.tsx:55`               | `errors.network`                            | sidecar boot, CORS, 5xx, fetch type error            |
| `routes/lock.tsx:76`               | `err.message` (raw, no i18n)                | toute erreur init non-400                            |
| `routes/dashboard.encrypt.tsx:60`  | `errors.network`                            | sidecar lent, 5xx, fetch type error                  |
| `routes/dashboard.encrypt.tsx:58`  | `err.detail` (server string, peut-être EN)  | 4xx non-409 — i18n leak                              |
| `routes/dashboard.decrypt.tsx:59`  | `errors.network`                            | sidecar lent, fetch type error                       |
| `routes/dashboard.decrypt.tsx:57`  | `err.detail` (server string)                | 4xx non-422 (pre-KDF parse) — i18n leak              |
| `routes/dashboard.share.tsx:88`    | `errors.network`                            | sidecar lent, fetch type error                       |
| `routes/dashboard.share.tsx:87`    | `err.detail` (server string)                | toute 4xx — i18n leak                                |
| `routes/dashboard.accept.tsx:81`   | `errors.network`                            | sidecar lent, fetch type error                       |
| `routes/dashboard.accept.tsx:79`   | `err.detail` (server string)                | 4xx non-422 — i18n leak                              |
| `routes/dashboard.users.tsx:45,56` | `errors.network`                            | toute erreur non-409/non-400                         |
| `routes/dashboard.history.tsx:32`  | `errors.network`                            | toute erreur audit verify                            |
| `api/sidecar.ts:40`                | thrown `Error("sidecar handshake ... 10s")` | bubble vers `errors.network` — pas de surface dédiée |
| `api/client.ts:74`                 | `SidecarHttpError(status, statusText)`      | si JSON parse échoue, statusText anglais brut        |

**Pattern global** : 12 catch blocks compressent tout en `errors.network`. La
remediation P0-2 doit produire 4 codes d'erreur typés
(`SidecarUnreachable.handshake`, `.fetch`, `.timeout`, `SidecarHttpError`)
et 4 toasts distincts. Pas plus, pas moins.

## Quick wins

1. **(15 min)** Supprimer `App.tsx` (P2-2).
2. **(20 min)** Ajouter le confirm-password + ack checkbox sur init flow
   (P0-6) - block-out feature, pas de risk.
3. **(30 min)** Extraire `<LanguageToggle />` (P2-3).
4. **(45 min)** Durcir `defaultOptions.queries.retry` (P1-2) - une seule
   ligne dans `main.tsx`.
5. **(45 min)** Ajouter un compte à rebours auto-lock dans `dashboard.tsx`
   (P1-3) - améliore drastiquement la confiance utilisateur.
6. **(60 min)** Wrapper le `<Outlet />` racine avec react-error-boundary
   (P1-1) - simple, déjà installé.
7. **(60 min)** Remplacer `window.confirm` par `<AlertDialog>` (P1-7).
8. **(2 h)** Implémenter le typed-error split P0-2 (le plus impactant
   pour l'UX prod-ready).
9. **(2 h)** Ajouter le BootSplash + SidecarUnreachable lock screen
   (P0-1) - **avant tout le reste** : c'est le 1er écran que voit le
   reviewer.
10. **(30 min)** Désinstaller les ~25 deps mortes (P2-1) - boundary win
    visible dans `pnpm-lock.yaml` audit.
11. **(2 h)** Ajouter `data-tauri-drag-region` + `<WindowControls />`
    (P0-3) - **bloquant pour la démo**.
12. **(1 h)** Resserrer `capabilities/default.json` en virant les
    `:default` (P0-4) - lecture sécurité reviewer immédiate.

Total quick wins : ~12 h pour stabiliser l'UX au niveau soutenance.
P0-1, P0-2, P0-3, P0-4 sont obligatoires; P0-5, P0-6, P0-7 fortement
recommandés.

=== AUDIT COMPLETE ===
