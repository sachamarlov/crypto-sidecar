# 000 — Tauri frontend (React 19)

- Status: draft
- Owner: Claude Opus 4.7 (implementation), @sachamarlov (review)
- Tracks: F-10 (Modern desktop GUI) from `docs/SPEC.md`. Consumes the
  Tauri sidecar HTTP API (spec `000-tauri-sidecar`).

## Behaviour

A React 19 + Vite SPA running inside the Tauri 2 WebView2 window.
The frontend mirrors the CLI / TUI surface (lock / dashboard /
encrypt / decrypt / share / accept / history / users / settings)
and talks to the Python sidecar over loopback HTTP using the
`(port, token)` pair retrieved via the Tauri command
`get_sidecar_connection`.

Key technologies:

- **React 19 + Vite 6** — bundle, HMR, code splitting.
- **TanStack Router** (file-based) — typed routes, AuthGuard.
- **TanStack Query** + **openapi-typescript** — API cache + typed
  client generated from the sidecar's `/openapi.json`.
- **shadcn/ui + Radix + Tailwind v4** — accessible primitives.
- **Framer Motion** — micro-interactions; respects
  `prefers-reduced-motion`.
- **Jotai** — lock state (atomic, finely-grained reactivity).
- **Zustand** — UI globals (theme, language).
- **react-hook-form + Zod** — form validation.
- **react-i18next** — FR + EN.
- **sonner** — toast notifications (anti-oracle uniform on decrypt).

## Acceptance criteria (Gherkin)

```gherkin
Scenario: Lock screen unlocks the vault
  Given an initialised vault
  When the user enters the admin password and presses "Déverrouiller"
  Then the frontend POSTs /api/v1/vault/unlock
  And on 200 the session_id is stored in Jotai vaultUnlockedAtom
  And the user is redirected to /dashboard

Scenario: Lock screen anti-oracle on wrong password
  Given an initialised vault
  When the user enters a wrong password
  Then a Sonner toast displays a constant generic message
  And no part of the UI reveals whether the vault exists or the password is wrong

Scenario: Encrypt round-trip via the GUI
  Given the vault is unlocked
  When the user picks a file and submits the encrypt form
  Then a .crypt is written to disk (alongside the source by default)
  And the dashboard refreshes its vault items list

Scenario: Decrypt anti-oracle preservation
  Given a tampered .crypt file
  When the user attempts to decrypt with the right password
  Then the toast text is byte-identical to the wrong-password toast
  And no plaintext is written to disk

Scenario: Share token round-trip
  Given two local users alice + bob
  When alice produces a .gbox-share for bob with fingerprint confirm
  Then the token's RSA-PSS signature verifies with bob's frontend
  And bob's accept flow reproduces the original plaintext byte-by-byte

Scenario: Auto-lock on idle
  Given the vault is unlocked
  When auto_lock_minutes elapses without a request
  Then the frontend redirects to /lock
  And the session is closed via POST /api/v1/vault/lock

Scenario: i18n switch
  Given the user is on /dashboard in French
  When they switch the language to English from the header
  Then every visible string changes to English
  And the choice persists across reloads

Scenario: WCAG 2.2 AA on every screen
  Given any screen of the app
  When axe-playwright runs an a11y audit
  Then there are zero violations at WCAG 2.2 AA
```

## Non-functional requirements

| ID    | Requirement                                                   |
| ----- | ------------------------------------------------------------- |
| NFR-3 | Cold start GUI < 1.5 s on a modern laptop SSD.                |
| NFR-6 | Every UI string localised in FR + EN.                         |
| NFR-7 | WCAG 2.2 AA on all screens via axe-playwright.                |
| NFR-8 | Vitest coverage ≥ 80 % global, ≥ 95 % on `api/` and `hooks/`. |

## Out of scope (post-MVP)

- Drag-and-drop encrypt from the OS file manager.
- Multi-window (currently a single Tauri window).
- Custom theming beyond the bundled dark / light.
- Command palette (cmd-K) — a follow-up once the screen surface
  stabilises.
