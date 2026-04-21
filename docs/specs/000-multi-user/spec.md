# 000 — Multi-user vault + persistence layer

- Status: draft
- Owner: Claude Opus 4.7 (implementation), @sachamarlov (review)
- Tracks: F-8 (multi-user SQLite), F-9 (audit log) from `docs/SPEC.md`
- Related ADRs: 0003 (superseded), 0011 (cross-platform DB encryption)

## Behaviour

GuardiaBox supports several **local** users sharing the same install. Each
user has their own keystore (master password → vault key → wrapped RSA
keypair). All actions are appended to a hash-chained audit log.

The persistence layer is dual-backend (Linux SQLCipher / Win+Mac
column-level AES-GCM, see ADR-0011). The schema is identical regardless
of the backend selected at runtime; only the mechanism that protects
sensitive columns differs.

## Acceptance criteria (Gherkin)

```gherkin
Scenario: Create a new local user
  Given a clean GuardiaBox installation
  When I run "guardiabox user create alice"
  And I supply a strong master password (zxcvbn score >= 3)
  Then the vault DB contains a row in `users` with username "alice"
  And the row's `salt` is 16 random bytes
  And the row's `wrapped_vault_key` decrypts back to a 32-byte AES key
  And the row's `wrapped_rsa_private` decrypts back to a valid RSA key
  And an audit_log entry "user.create" is appended

Scenario: Cannot create two users with the same name
  Given a user "alice" already exists
  When I run "guardiabox user create alice"
  Then the operation fails with "username already taken"
  And the DB state is unchanged

Scenario: Unlock returns the vault key without leaking the password
  Given a user "alice" exists with master password P
  When I call security.keystore.unlock(alice_keystore, P)
  Then the call returns the 32-byte vault key
  And the master password is never persisted
  And an audit_log entry "user.unlock" is appended

Scenario: Failed unlock increments a backoff counter
  Given a user "alice" exists
  When I call unlock with the wrong password 3 times
  Then user.failed_unlock_count == 3
  And subsequent unlock calls within 30 seconds raise a backoff error
  And an audit_log entry "user.unlock_failed" is appended for each attempt

Scenario: Audit log integrity (hash chain)
  Given the audit log has N entries
  When I tamper with entry N-2 (modify metadata)
  And I run "guardiabox doctor --verify-audit"
  Then the verification fails at entry N-1 (whose prev_hash no longer matches)

Scenario: Column-level encryption on Win/Mac
  Given the runtime is Windows or macOS
  And SQLCipher is not available
  When a vault_item is inserted with filename "tax-returns.pdf"
  Then `SELECT filename FROM vault_items` returns ciphertext bytes, not the plaintext
  And the value can be decrypted by the column-level helper using the vault key
  And an HMAC-SHA-256 index column allows equality lookup on the encrypted value
```

## Out of scope (future specs)

- Cross-machine user sync (requires the sync server, post-CDC).
- SSO / OIDC integration.
- Hardware-backed keystores (YubiKey PIV, TPM) — roadmap post-CDC.
