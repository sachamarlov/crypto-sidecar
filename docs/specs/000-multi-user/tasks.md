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

## Phase C-2 — CLI surface + integration (PR #26)

- [x] **T-000mu.09** — `ui.cli.commands.user` sub-Typer
      (`create`, `list`, `show`, `delete --yes`). Prompts for vault
      admin password + per-user master password via `read_password`;
      emits `user.create` / `user.delete` audit entries.
      _Out of MVP scope_: `export-pubkey` / `import-pubkey` deferred
      to spec 003 (rsa-share) — they only make sense with a sharing
      flow.
- [x] **T-000mu.10** — `ui.cli.commands.history` (`--limit`,
      `--user`, `--action`, `--format json|table`). Decrypts target + metadata with the unlocked vault admin key. CSV format
      deferred (table + json cover the two real consumers).
- [x] **T-000mu.11** — `ui.cli.commands.doctor` with
      `--verify-audit` (full chain scan; prints `[OK] intègre` /
      `[FAIL] altération détectée à sequence=N`). Plain `doctor`
      reports paths + SQLCipher availability without unlocking.
- [x] **T-000mu.12** — `ui.cli.commands.init` boot command. Backed
      by `persistence.bootstrap.init_vault`: creates `data_dir`,
      writes `vault.admin.json` (salt + KDF params),
      `alembic upgrade head`, appends `system.startup` audit row at
      sequence 1.
- [x] **T-000mu.13** — `--vault-user <name>` opt-in flag on
      `encrypt` / `decrypt`. When present, after the .crypt file
      lands, the CLI opens a vault session under the admin password,
      persists a `vault_items` row (encrypt only), and appends a
      `file.encrypt` / `file.decrypt` audit row. Unknown user ⇒
      `VaultUserNotFoundError` ⇒ `ExitCode.PATH_OR_FILE`. The
      single-user CLI without the flag is unchanged.

## Definition of Done

### Phase C-1 (PR #25, merged)

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
| Coverage floor (core + security ≥ 95 %) | ✅ enforced on full-suite CI                |

### Phase C-2 (this PR)

| Gate                                                   | Status                                         |
| ------------------------------------------------------ | ---------------------------------------------- |
| `vault_admin` config + key derivation                  | ✅ 11 unit + 6 slow tests                      |
| `init` bootstrap (data_dir + alembic + genesis)        | ✅ 5 integration (subprocess + CliRunner)      |
| `user create / list / show / delete`                   | ✅ 5 subprocess + 8 in-process flow tests      |
| `history` (table / json / filter user / filter action) | ✅ 3 subprocess + 4 in-process + 4 CliRunner   |
| `doctor` (paths + `--verify-audit` clean + tampered)   | ✅ 3 subprocess + 4 in-process tests           |
| `--vault-user` audit hook on encrypt / decrypt         | ✅ 4 integration (encrypt + decrypt + unknown) |
| Coverage floor (core + security ≥ 95 %)                | ✅ core 99.61 %, security 97.53 %              |
| Ruff / Mypy strict / Bandit                            | ✅ all green                                   |

Subprocess tests catch CLI bootstrap regressions (argument parsing,
asyncio teardown, Windows cp1252 console encoding); in-process tests
drive the same async flows under `pytest-cov` so the modules show up
in the coverage report. Both layers are kept on purpose — see the
docstring of `tests/integration/test_cli_phase_c2_inprocess.py`.
