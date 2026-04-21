# 000 — Multi-user — technical plan

## Touched modules

- `guardiabox.persistence.models` — declarative `Base`, `User`,
  `VaultItem`, `Share`, `AuditEntry`.
- `guardiabox.persistence.database` — `create_engine` (dual backend),
  `session_scope` (async).
- `guardiabox.persistence.repositories` — `UserRepository`,
  `VaultItemRepository`, `ShareRepository`, `AuditRepository`.
- `guardiabox.persistence.migrations/` — Alembic env + initial migration.
- `guardiabox.security.keystore` — `create`, `unlock`, key wrap/unwrap.
- `guardiabox.security.audit` — append + verify hash-chained log.
- `guardiabox.core.crypto` — new helpers `encrypt_column` /
  `decrypt_column` for the Win/Mac fallback (covered also by spec 002).
- `guardiabox.ui.cli.commands.user` — `user create / list / delete /
export-pubkey / import-pubkey`.
- `guardiabox.ui.cli.commands.history` — `history --limit N --user U`.

## Backend selection

```python
def create_engine(database_url: str, *, vault_admin_password: str) -> AsyncEngine:
    try:
        import sqlcipher3            # noqa: F401 — availability probe
    except ImportError:
        return _create_vanilla_engine(database_url)
    return _create_sqlcipher_engine(database_url, vault_admin_password)
```

The repository layer accepts both engines transparently. When the engine
is vanilla SQLite, `VaultItemRepository.create()` calls
`encrypt_column(filename, vault_key)` before insertion ; reads call
`decrypt_column(blob, vault_key)`.

## Audit log integrity

Each entry has columns `(sequence, ..., prev_hash, entry_hash)` where
`entry_hash = SHA-256(prev_hash || canonical_json(other_columns))`.
`prev_hash` references the previous row's `entry_hash` (genesis = 32
zero bytes). A SQL trigger refuses `UPDATE` and `DELETE` on the table.
A `verify()` method scans the chain from sequence 1 to N and reports
the first inconsistency.

## Backoff policy

Failed unlocks increment `failed_unlock_count`. The lockout window is
exponential: `2 ** min(failed_unlock_count, 9)` seconds (capped at
~ 15 minutes), reset on a successful unlock.

## Test plan

- **Unit** — repositories CRUD against an in-memory `aiosqlite://`.
- **Integration** — lifecycle test: create user → encrypt file → share
  with second user → second user accepts → first user runs
  secure-delete → audit chain verifies.
- **Property** — round-trip arbitrary `(filename, metadata)` through
  the column-level encryption helpers, backend = vanilla SQLite.
- **Security** — fuzz the audit log file with random bit flips, expect
  the verifier to detect every alteration.

## Open questions

- Do we expose a vault administrator password separate from each
  user's master password ? Current proposal: yes, a dedicated admin
  password protects the SQLCipher key (or the column-level master) and
  is set at `guardiabox init`. To revisit if it complicates the UX
  excessively.
