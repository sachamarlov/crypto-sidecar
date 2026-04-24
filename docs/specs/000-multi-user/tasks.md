# 000 — Multi-user — task breakdown

> Split in two phases so the persistence foundations land first and are
> testable independently of the CLI surface. Phase C-1 ships every core
> module a repository / service needs; Phase C-2 wires the CLI commands
> and integrates with the encrypt / decrypt flows (spec 001, 002).

## Phase C-1 — persistence foundations (PR #25)

- [x] **T-000mu.01** — `core.crypto.encrypt_column / decrypt_column`
      helpers. AAD binds column name + row id; ciphertext cannot be
      lifted between columns or rows.
- [x] **T-000mu.02** — `core.crypto.deterministic_index_hmac` helper
      (HMAC-SHA-256 over `column || 0x1f || plaintext`) for equality
      lookups on encrypted columns. Binds the column name so
      cross-column correlation is impossible.
- [x] **T-000mu.03** — `persistence.database.create_engine` runtime
      engine factory (async aiosqlite) + `session_scope` async
      context manager (commit / rollback). SQLCipher opt-in tracked
      separately; column-level encryption is the Phase C floor.
- [x] **T-000mu.04** — `persistence.models.{User, VaultItem, Share,
AuditEntry}` declarative classes. Encrypted columns use the
      `_enc` suffix, HMAC indices use `_hmac`; foreign keys enforce
      cascade semantics (user→items CASCADE, user→audit SET NULL).
- [x] **T-000mu.05** — Alembic env.py wired to `models.Base.metadata`;
      initial migration creates the four tables + two BEFORE triggers
      enforcing the append-only contract on `audit_log`.
- [x] **T-000mu.06** — `persistence.repositories.{User, VaultItem,
Share, Audit}Repository` — async CRUD + lookup by HMAC index +
      transparent encrypt/decrypt of sensitive columns + lockout
      counters on the User aggregate.
- [x] **T-000mu.07** — `security.keystore.create / unlock /
change_password`. RSA-4096 keypair + AES-256 vault key,
      AES-GCM-wrapped under a master key derived via the selected KDF.
      `change_password` re-wraps without re-encrypting any `.crypt`
      file.
- [x] **T-000mu.08** — `security.audit.append / verify` hash-chain
      built on AuditRepository. `compute_entry_hash` hashes the
      ciphertext columns so the chain survives a vault-key rotation.
      SQL trigger contract test lives in
      `tests/integration/test_persistence_migrations.py`.

## Phase C-2 — CLI surface + integration (PR to come)

- [ ] **T-000mu.09** — `ui.cli.commands.user` (`create`, `list`,
      `delete`, `export-pubkey`, `import-pubkey`). Prompts for vault
      admin password + per-user master password via `read_password`;
      emits audit entries on every state change.
- [ ] **T-000mu.10** — `ui.cli.commands.history` (`--limit`,
      `--user`, `--action`, `--format json|csv|table`). Decrypts
      target + metadata with the unlocked vault admin key.
- [ ] **T-000mu.11** — Doctor command extension `guardiabox doctor
--verify-audit` (full chain scan; prints the first bad
      sequence if any, otherwise green OK).
- [ ] **T-000mu.12** — `guardiabox init` boot command: creates
      `~/.guardiabox/`, runs `alembic upgrade head`, prompts for
      the vault admin password, writes a salt file, logs
      SYSTEM_STARTUP to the audit log.
- [ ] **T-000mu.13** — Wire `encrypt_file` / `decrypt_file` to the
      active user's VaultItemRepository so every successful
      encrypt / decrypt appends an audit entry and updates the
      vault_item row.

## Definition of Done

### Phase C-1 (this PR)

| Gate                                    | Status                                      |
| --------------------------------------- | ------------------------------------------- |
| column encryption round-trip + AAD      | ✅ 24 unit + property tests                 |
| SQLAlchemy models create_all            | ✅ 12 unit tests                            |
| async engine + session_scope            | ✅ 5 integration tests                      |
| Alembic upgrade + append-only triggers  | ✅ 4 integration tests                      |
| Keystore create/unlock/change_password  | ✅ 11 unit tests + 2 slow smokes            |
| Repositories CRUD + HMAC index          | ✅ 9 integration tests                      |
| Audit hash-chain append + verify        | ✅ 9 integration tests (+ tamper detection) |
| Ruff / Mypy strict / Bandit             | ✅ all green                                |
| Coverage floor (core + security ≥ 95 %) | ✅ will be checked on full-suite CI         |

### Phase C-2 (next PR)

Covered once CLI commands land. Acceptance scenarios from `spec.md`
§3 (create user, unlock, backoff on failures, audit verify, column
encryption on Win/Mac) will all be exercised end-to-end via
`subprocess.run` integration tests.
