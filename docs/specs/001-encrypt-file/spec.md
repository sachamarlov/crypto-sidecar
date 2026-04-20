# 001 — Encrypt a file (or a typed message)

* Status: draft
* Owner: Claude Opus 4.7 (implementation), @sachamarlov (review)
* Tracks: F-1, F-3, F-5, F-6 from `docs/SPEC.md`

## Behaviour

The user invokes `guardiabox encrypt <PATH>` (CLI), the equivalent TUI
action, or the Tauri shell's encrypt flow. They supply a password — typed
in a no-echo prompt for the CLI/TUI and a masked input for the GUI. The
system writes a sibling `<PATH>.crypt` file containing the
authenticated ciphertext.

For *messages*, the user invokes `guardiabox encrypt --message` with `-m
<TEXT>` or pipes via stdin, plus `-o <OUTPUT>.crypt`.

## Acceptance criteria (Gherkin)

```gherkin
Scenario: Round-trip a binary file
  Given a 1 MiB random file "data.bin"
  And a password of zxcvbn score >= 3
  When I encrypt "data.bin"
  And then decrypt the resulting "data.bin.crypt"
  Then the decrypted bytes equal the original bytes

Scenario: Refuse a weak password
  Given a 6-character password "abc123"
  When I attempt to encrypt any file
  Then the operation fails with WeakPasswordError
  And the .crypt file is never created on disk
  And the human-facing error message hints at lengthening or adding diversity

Scenario: Refuse a path traversal
  Given target path "../../etc/passwd"
  When I attempt to encrypt
  Then the operation fails with PathTraversalError
  And no file is written outside the working directory tree

Scenario: Write atomically
  Given an encryption that is interrupted (process killed mid-write)
  When the user inspects the directory
  Then no partial "<file>.crypt" exists
  (only the temporary write file may exist; readers must skip it)

Scenario: Preserve the original file
  Given any successful encryption of "report.pdf" → "report.pdf.crypt"
  Then "report.pdf" is byte-identical to its pre-encryption state
  And its mtime is unchanged
```

## Out of scope (future specs)

* Bulk encryption (multi-file selection) — `005-bulk-encrypt`.
* Re-encryption with a new password — `006-rotate-password`.
* In-place encryption that securely deletes the original — `004-secure-delete`.
