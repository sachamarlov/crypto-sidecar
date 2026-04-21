# 000 — TUI (Textual)

- Status: draft
- Owner: Claude Opus 4.7 (implementation), @sachamarlov (review)
- Tracks: F-14 (Rich TUI for terminal-only environments)

## Behaviour

`guardiabox-tui` launches a full-screen Textual application that
mirrors the information architecture of the desktop GUI, scaled down
to the terminal grid. It is targeted at users who prefer a console
workflow (servers, dev environments, screen-readers via braille
displays) but want richer interactions than the line-oriented CLI.

The TUI is a _thin adapter_ over `guardiabox.core` — it does **not**
duplicate any business logic, it just composes screens around the
same operations the CLI invokes.

## Acceptance criteria (Gherkin)

```gherkin
Scenario: Application launches and shows the vault dashboard
  When I run "guardiabox-tui"
  Then the screen displays a Header with "GuardiaBox"
  And a sidebar listing local users
  And a main panel listing the active user's vault items in a DataTable
  And a Footer with key bindings (q quit, e encrypt, d decrypt, s share)

Scenario: Encrypt flow from the TUI
  Given a user is unlocked
  When I press "e" on the dashboard
  Then a modal opens prompting for a file (file picker) and a password
  And submitting valid inputs creates a `.crypt` file in the vault
  And the DataTable reflects the new entry without manual refresh
  And a Toast confirms the success

Scenario: Decrypt flow from the TUI
  When I select a `.crypt` row and press "d"
  Then a modal prompts for the password
  And on success the file is decrypted to a chosen output path
  And on failure the modal shows a generic "decryption failed" message

Scenario: Audit log viewer
  When I press "h" (history)
  Then a screen shows the audit entries in reverse-chronological order
  And filters allow restricting by user / action / date range
  And tampered entries (chain mismatch) are highlighted in red

Scenario: Keyboard-only navigation
  Given any screen
  When the user navigates with Tab / Shift-Tab / arrows / Enter
  Then every interactive element is reachable
  And the focused element shows a visible focus ring

Scenario: Reduced-motion mode
  Given the terminal does not support animations (TERM=dumb)
  When the TUI launches
  Then no animation is played
  And the layout still renders correctly
```

## Out of scope (future)

- Mouse support beyond what Textual provides by default.
- Vim-mode key bindings (planned post-MVP).
- Integration with an external diff tool for "preview" of encrypted
  files (planned post-MVP).
