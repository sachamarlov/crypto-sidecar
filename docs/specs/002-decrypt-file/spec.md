# 002 — Decrypt a `.crypt` file

* Status: draft (skeleton)
* Tracks: F-2, F-4 from `docs/SPEC.md`
* Depends on: spec 001 (the container format must already be implemented).

## Behaviour

The user invokes `guardiabox decrypt <PATH>.crypt` (or the equivalent in
TUI/GUI). They supply the password used to encrypt the file. On success a
sibling `<PATH>.decrypt` file is written; in `--message` mode the plaintext is
streamed to stdout.

## Acceptance criteria (Gherkin)

```gherkin
Scenario: Round-trip
  Given a "<file>.crypt" produced by spec 001
  And the original password
  When I run "guardiabox decrypt <file>.crypt"
  Then the bytes of "<file>.decrypt" equal the original plaintext

Scenario: Wrong password produces no partial output
  Given a valid .crypt file and a wrong password
  When I run "guardiabox decrypt <file>.crypt"
  Then no .decrypt file is created on disk
  And the exit code is 2
  And the stderr message is generic ("decryption failed")
  (no oracle distinguishing wrong password from tampering)

Scenario: Tampered ciphertext is detected
  Given a .crypt file whose final byte has been flipped
  When I run "guardiabox decrypt <file>.crypt" with the correct password
  Then it raises IntegrityError
  And no .decrypt file is created
```

## Failure-mode anti-oracle

The same generic error message and exit code is returned for *both* wrong
password and tampered ciphertext, so an attacker cannot distinguish the two
states by the system's response. (Internally the error class differs, for
audit logging.)

## Out of scope (future)

* Bulk decrypt of many files — `005-bulk-encrypt` covers the same surface.
* Streaming decryption to a downstream pipe (planned for v0.2).

## Plan / tasks

To be drafted before implementation begins (`plan.md`, `tasks.md`).
