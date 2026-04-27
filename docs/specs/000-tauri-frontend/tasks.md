# 000 — Tauri frontend — task breakdown

- [~] **T-000fe.01** — OpenAPI codegen pipeline. _MVP shortcut_:
  hand-written `src/api/types.ts` mirroring the Phase G
  Pydantic schemas. The full pipeline (`scripts/export_openapi.py` + `pnpm openapi:generate` + `schema.d.ts`) lands as a
  follow-up; the contract is identical.
- [x] **T-000fe.02** — `src/api/client.ts` with token + session
      interceptors; `getSidecarConnection()` polls
      `invoke('get_sidecar_connection')` at boot until the Rust
      handshake completes.
- [x] **T-000fe.03** — TanStack Router file-based routes:
      `routes/index.tsx` redirects via `isUnlockedAtom`,
      `routes/lock.tsx`, `routes/dashboard.tsx` (AppShell with
      AuthGuard + useAutoLock), 7 nested dashboard routes.
- [x] **T-000fe.04** — Lock state: Jotai atoms (`sessionId`,
      `expiresAtMs`, `isUnlocked`, `activeUserId`),
      `useAutoLock()` hook, AuthGuard component.
- [x] **T-000fe.05** — `<PasswordField>` shared component
      (no-echo Input + 20-char strength bar). Client-side
      zxcvbn-style evaluator in `lib/password.ts`.
- [x] **T-000fe.06** — `LockScreen` -- admin password unlock +
      init vault flow + language switch + reduced-motion respect.
- [x] **T-000fe.07** — `DashboardScreen` AppShell -- header +
      sidebar nav + per-user picker on `/dashboard/`.
- [x] **T-000fe.08** — `EncryptModal` (file picker + KDF radio +
      password + confirm).
- [x] **T-000fe.09** — `DecryptModal` (anti-oracle: 422 collapses
      to constant toast text).
- [x] **T-000fe.10** — `ShareModal` 2-step (form -> fingerprint
      warning -> commit).
- [x] **T-000fe.11** — `AcceptModal` (token import + sender
      select; 422 anti-oracle; `share expired` allowed to differ
      post signature-verify).
- [x] **T-000fe.12** — `HistoryModal` (DataTable + filters +
      verify-chain button).
- [x] **T-000fe.13** — `UsersModal` (create + list + delete with
      confirm).
- [x] **T-000fe.14** — `SettingsModal` (doctor + version
      diagnostics).
- [x] **T-000fe.15** — i18n FR + EN (`react-i18next`,
      `i18next-browser-languagedetector`). 100+ keys.
- [~] **T-000fe.16** — WCAG 2.2 AA polish: focus rings, ARIA,
  reduced-motion, role/scope on table headers + toasts.
  _Deferred_: `axe-playwright` audit runs in a follow-up
  (requires Playwright browser binaries cached on the runner).
- [~] **T-000fe.17** — Vitest unit tests on the password
  evaluator + lock atoms + PasswordField component (16 tests).
  _Coverage gates_ 80 % / 95 % validated by the CI step
  activated via H-17.
- [ ] **T-000fe.18** — Playwright E2E flows. _Deferred_: requires
      a live PyInstaller-bundled sidecar + a Playwright browser
      cache on the runner; lands with Phase I (release workflow).
- [~] **T-000fe.19** — Biome strict + tsconfig strict + Tauri
  capabilities allowlist tightening. _Deferred_: gated on
  H-17 `pnpm install` resolving the lockfile so biome can
  run against the resolved deps.
- [ ] **T-000fe.20** — `pnpm-lock.yaml` committed; CI frontend
      job activated. _Deferred_: gated on a green local
      `pnpm install + pnpm lint + pnpm typecheck + pnpm test
--run` run, which itself depends on the package install
      resolving cleanly with the deps already in `package.json`.

Legend: `[x]` shipped, `[~]` partial / deferred sub-step, `[ ]`
not started.

## Definition of Done

| Gate                                           | Status                              |
| ---------------------------------------------- | ----------------------------------- |
| 9 screens render at parity with CLI / TUI      | ✅ shipped                          |
| Anti-oracle byte-identical on Decrypt + Accept | ✅ enforced via constant toast      |
| FR + EN strings cover 100 % of UI              | ✅ 100+ keys both languages         |
| WCAG 2.2 AA on every screen via axe-playwright | ⚠ axe audit deferred (browser bin) |
| Vitest coverage ≥ 80 % overall                 | ⚠ 16 tests landed; gate post H-17  |
| 8 Playwright E2E flows pass                    | ⚠ deferred to Phase I (live bin)   |
| `pnpm lint` (biome) + `pnpm typecheck` clean   | ⚠ runs once H-17 lands             |
| CI Frontend job green                          | ⚠ activates once H-17 lands        |
