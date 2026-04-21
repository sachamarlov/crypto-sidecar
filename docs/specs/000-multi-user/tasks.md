# 000 — Multi-user — task breakdown

- [ ] **T-000mu.01** — `core.crypto.encrypt_column / decrypt_column`
      helpers + property tests (round-trip on arbitrary bytes ; AAD binds
      column name + row id to prevent cross-substitution).
- [ ] **T-000mu.02** — `core.crypto.deterministic_index_hmac` helper
      (HMAC-SHA-256 over `key || column_name || plaintext`) for equality
      lookups on encrypted columns.
- [ ] **T-000mu.03** — `persistence.database.create_engine` runtime
      backend probe (`try: import sqlcipher3`) + factory split.
- [ ] **T-000mu.04** — `persistence.models.{User,VaultItem,Share,AuditEntry}`
      declarative classes ; encrypted columns typed as `bytes` + companion
      `*_index` HMAC column.
- [ ] **T-000mu.05** — Alembic env.py wired to `models.Base.metadata` ;
      initial migration that creates all 4 tables + audit-log
      append-only trigger.
- [ ] **T-000mu.06** — `persistence.repositories.UserRepository` (CRUD
  - lockout counters) ; idem for VaultItem / Share / Audit.
- [ ] **T-000mu.07** — `security.keystore.create / unlock / change_password`
      ; `change_password` re-wraps the vault key + RSA private without
      re-encrypting any `.crypt` file.
- [ ] **T-000mu.08** — `security.audit.append / verify` with hash chain
  - SQL trigger contract test.
- [ ] **T-000mu.09** — `ui.cli.commands.user` (create / list / delete /
      export-pubkey / import-pubkey) + E2E subprocess tests.
- [ ] **T-000mu.10** — `ui.cli.commands.history` (`--limit`, `--user`,
      `--action`, `--format json|csv|table`) + E2E.
- [ ] **T-000mu.11** — Doctor command extension `guardiabox doctor
--verify-audit` (full chain scan).

Definition of Done: every acceptance scenario from `spec.md` passes ;
coverage ≥ 95 % on `persistence/`, `security/keystore`, `security/audit` ;
bandit clean ; mypy strict clean ; both backends exercised in CI matrix.
