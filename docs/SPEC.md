# SPEC — GuardiaBox product specification

> Source of truth for **what** the product does, for **whom**, and **how we
> know it works** (acceptance criteria). The technical "how" lives in
> `ARCHITECTURE.md`, the security model in `THREAT_MODEL.md`, and per-feature
> implementation plans in `docs/specs/`.

## 1. Mission

Provide a **local-first, zero-cloud** secure vault that lets a single user (or
a small group of users sharing one machine) encrypt files and short messages,
keep them encrypted at rest, share them safely between local accounts, and
delete them irrecoverably — without ever trusting a remote server.

## 2. Personas

| Persona             | Who they are                                         | What they want                                                              |
| ------------------- | ---------------------------------------------------- | --------------------------------------------------------------------------- |
| **Sasha** (primary) | Privacy-aware power-user on Windows 11               | Encrypt arbitrary files quickly; trust no SaaS; verifiable security         |
| **Marie** (sharer)  | Sasha's colleague who needs one specific document    | Receive a single shared file safely; minimum friction                       |
| **Alex** (auditor)  | Reviews the project for academic / professional eval | Walk through the code & docs; verify cryptographic decisions are defensible |

## 3. Functional scope

### 3.1 In scope (MVP — required by the academic brief)

- **F-1 — Encrypt a file or a message** with a user-supplied password.
- **F-2 — Decrypt a `.crypt` file** back to its original content given the password.
- **F-3 — Encrypt a typed message** into a fresh `.crypt` file.
- **F-4 — Decrypt and view a message** without writing it to disk.
- **F-5 — Reject weak passwords** (zxcvbn score ≥ 3, length ≥ 12).
- **F-6 — Refuse path-traversal inputs** (e.g. `../../etc/passwd`).
- **F-7 — Console menu** (interactive CLI) listing encrypt / decrypt / quit.

### 3.2 In scope (extensions — explicitly required for top grade)

- **F-8 — Multi-user accounts** with per-user keystores in a SQLCipher DB.
- **F-9 — Audit log** of every security-relevant action (hash-chained).
- **F-10 — Modern desktop GUI** (Tauri 2 + React + shadcn).
- **F-11 — Asymmetric sharing** (RSA-OAEP wrap of an AES key, exported to a
  `.gbox-share` file the recipient imports).
- **F-12 — Secure delete** of plaintext files (DoD multi-pass overwrite +
  cryptographic erase).
- **F-13 — Argon2id KDF** as opt-in alternative to PBKDF2.
- **F-14 — Rich TUI** (Textual) for terminal-only environments.

### 3.3 Explicitly out of scope

- ❌ Cloud sync, remote accounts, any networking beyond loopback.
- ❌ Browser extension, mobile app.
- ❌ Hardware token integration (deferred — see roadmap below).
- ❌ Password generator (use the OS / browser one).
- ❌ Self-destructing time-bombed shares (cryptographic primitives only;
  enforcement would require a trusted third party).

## 4. Non-functional requirements

| ID    | Requirement                                                              |
| ----- | ------------------------------------------------------------------------ |
| NFR-1 | Encrypt + decrypt ≥ 100 MiB/s on a modern laptop SSD.                    |
| NFR-2 | KDF derivation completes in 50 ms ≤ T ≤ 1 s on the same hardware.        |
| NFR-3 | Cold start of CLI < 200 ms; cold start of GUI < 1.5 s.                   |
| NFR-4 | Memory footprint of sidecar < 100 MiB at idle.                           |
| NFR-5 | Distributable binary (Windows) ≤ 80 MiB after PyInstaller + Tauri build. |
| NFR-6 | All UI strings localised (FR + EN) via `react-i18next`.                  |
| NFR-7 | WCAG 2.2 AA accessibility on the GUI.                                    |
| NFR-8 | Test coverage ≥ 80 % overall, ≥ 95 % for `core/` and `security/`.        |
| NFR-9 | All CI checks (lint, type, tests, security) green for every merge.       |

## 5. Acceptance criteria — F-1 (Encrypt a file)

```gherkin
Feature: Encrypt a file
  As Sasha
  I want to encrypt a sensitive file with a strong password
  So that nobody can read its content without that password

  Scenario: Encrypt a small text file
    Given a file "invoice.pdf" of size 1.2 MiB on disk
    And a password of zxcvbn score >= 3
    When I run "guardiabox encrypt invoice.pdf"
    And I supply the password when prompted
    Then a file "invoice.pdf.crypt" is created in the same directory
    And the original "invoice.pdf" is left untouched
    And the new file starts with the magic bytes "GBOX"
    And the new file's size is original_size + header_size + tag_size

  Scenario: Refuse a weak password
    Given a password of zxcvbn score < 3
    When I run "guardiabox encrypt anything.txt"
    And I supply the weak password
    Then the command exits with code 1
    And no .crypt file is created
    And stderr contains a hint about strengthening the password

  Scenario: Refuse a path-traversal target
    Given any password
    When I run "guardiabox encrypt ../../etc/passwd"
    Then the command exits with code 1
    And stderr mentions a path-validation error
```

## 6. Acceptance criteria — F-2 (Decrypt a file)

```gherkin
Feature: Decrypt a file
  As Sasha
  I want to recover the original file given the correct password

  Scenario: Round-trip decryption
    Given a "report.pdf.crypt" produced by F-1 from "report.pdf" with password P
    When I run "guardiabox decrypt report.pdf.crypt"
    And I supply the password P
    Then a file "report.pdf.decrypt" appears whose bytes equal "report.pdf"

  Scenario: Wrong password is rejected without partial output
    Given the same .crypt file and a wrong password
    When I run "guardiabox decrypt report.pdf.crypt"
    Then no .decrypt file is created on disk
    And stderr describes a generic decryption failure
    And the exit code is 2
```

## 7. Roadmap (post-MVP)

- 🚀 Hardware-token unlock (YubiKey / Windows Hello via WebAuthn).
- 🚀 TOTP / passkey second factor.
- 🚀 Local LAN sync between two trusted instances (still zero-cloud).
- 🚀 Mobile companion (read-only) via Capacitor.

## 8. Glossary

- **`.crypt`** — GuardiaBox's authenticated-encryption container format.
- **KDF** — Key Derivation Function (PBKDF2 or Argon2id here).
- **AEAD** — Authenticated Encryption with Associated Data (AES-GCM here).
- **Vault key** — random AES-256 key per user, wrapped under the master key.
- **Cryptographic erase** — destroying the encryption key to render data
  unrecoverable, faster and more reliable than overwrite on flash storage.
