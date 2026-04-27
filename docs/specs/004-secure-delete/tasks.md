# 004 — Secure delete — task breakdown

> Split in two phases to avoid coupling with the keystore:
>
> - **Phase B1** (this PR): DoD multi-pass overwrite + cross-platform
>   SSD detection + CLI command. Fully prod-ready for HDD media; SSD
>   paths get a documented NIST SP 800-88r2 warning.
> - **Phase B2** (after spec 000-multi-user): crypto-erase backed by
>   the per-user keystore, wider `--method` surface.

## Phase B1 — overwrite + SSD detection

- [x] **T-004.01** — `core.secure_delete.SecureDeleteMethod` enum (only
      `OVERWRITE_DOD` exposed until Phase B2) + `secure_delete()` dispatch.
- [x] **T-004.02** — `core.secure_delete._overwrite_dod()` real
      implementation (zero / one / random pass cycle, fsync per pass,
      configurable pass count via `--passes N`). Unit tests on
      `tmp_path` assert the file disappears and multi-pass bytes
      differ from the original.
- [x] **T-004.03** — `SecureDeleteMethod.CRYPTO_ERASE` exposed; the
      flow lives in `ui.cli.commands.secure_delete._crypto_erase_flow`
      (DB lookup + DoD overwrite + row delete + audit). The pure-core
      `secure_delete()` raises `ValueError("vault-aware caller")` on
      `CRYPTO_ERASE` to keep the core free of DB / audit dependencies.
- [x] **T-004.04** — `core.exceptions.KeyNotFoundError` (vault_items
      lookup miss) and `CryptoEraseRequiresVaultUserError` (mode
      invoked without `--vault-user`). Both routed by `exit_for`.
- [x] **T-004.05** — `fileio.platform.is_ssd()` Windows path via
      `IOCTL_STORAGE_QUERY_PROPERTY` + `StorageDeviceSeekPenaltyProperty`
      through `ctypes`.
- [x] **T-004.06** — `fileio.platform.is_ssd()` Linux path: walk the
      block device from `/sys/dev/block/<major>:<minor>` and read
      `queue/rotational`.
- [x] **T-004.07** — `fileio.platform.is_ssd()` macOS path: call
      `diskutil info -plist` (resolved via `shutil.which`), parse
      `SolidState` / `MediaType` from the plist.
- [x] **T-004.08** — `ui.cli.commands.secure_delete` Typer command with
      `--method auto|overwrite` and `--passes` (1..35).
- [x] **T-004.09** — Confirmation prompt when the user requests overwrite
      on a detected SSD; `--no-confirm` to bypass.
- [x] **T-004.10** — `file.secure_delete` audit row appended via
      `security.audit.append` (Phase C hash-chain). Metadata =
      `{method, passes, vault_item_id}`.
- [ ] **T-004.11** — _Deferred post-MVP_: forensic Linux-tmpfs
      integration test (large payload, dedicated CI job). The
      mid-runtime cost is incompatible with the current 2-day pre-
      soutenance budget. Tracked as a follow-up; the existing 5
      integration tests cover every observable behaviour at unit /
      CLI granularity.
- [x] **T-004.12** — `guardiabox doctor --report-ssd` flag added
      (calls `fileio.platform.is_ssd` and reports SSD / HDD / unknown
      with the relevant recommendation).

## Phase B2 — crypto-erase (post-Phase D)

Honest scope (cf. ADR-0011 + THREAT_MODEL §4.6 update): GuardiaBox does
not currently persist a per-file DEK separate from the `.crypt` payload.
What ships in Phase B2 is **metadata-erase + ciphertext overwrite +
audit attribution**, not a strict NIST SP 800-88 crypto-erase. The
mode rejects calls without `--vault-user` because the metadata path is
what makes the option meaningful versus a plain overwrite. A true
DEK-destruction crypto-erase requires a `.crypt` v2 format with a
random per-file DEK persisted separately from the ciphertext —
roadmapped post-MVP.

## Definition of Done (Phase B1)

| Gate                             | Status                                                           |
| -------------------------------- | ---------------------------------------------------------------- |
| HDD acceptance scenario          | ✅ covered by CLI + unit tests                                   |
| SSD warning + confirmation       | ✅ `test_secure_delete_on_ssd_prompts_and_aborts`                |
| Path traversal / missing file    | ✅ exits 3 (`ExitCode.PATH_OR_FILE`)                             |
| `is_ssd` cross-platform contract | ✅ `tests/unit/test_platform.py` (soft assertion)                |
| Coverage — `core/secure_delete`  | ✅ 94.12 % (missing branches are defensive Windows-only asserts) |
| Coverage — `fileio/platform`     | ✅ 100 % of the branches executable on the host OS               |
| Ruff / Mypy strict / Bandit      | ✅ all green                                                     |

## Definition of Done (Phase B2)

| Gate                                                                           | Status                                                                |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------- |
| Crypto-erase round-trip (vault row deleted + .crypt unlinked + audit appended) | ✅ `test_crypto_erase_removes_row_and_unlinks_crypt`                  |
| `--method crypto-erase` rejects calls without `--vault-user`                   | ✅ `test_crypto_erase_without_vault_user_rejected` (exit USAGE)       |
| `KeyNotFoundError` on stray `.crypt` (no matching vault_items row)             | ✅ `test_crypto_erase_unknown_filename_raises_key_not_found` (exit 3) |
| `doctor --report-ssd` emits a verdict                                          | ✅ `test_doctor_report_ssd_emits_verdict`                             |
| `--help` advertises the new method                                             | ✅ `test_secure_delete_help_lists_crypto_erase_method`                |
| Pure-core `secure_delete()` rejects CRYPTO_ERASE                               | ✅ `test_secure_delete_rejects_crypto_erase_at_pure_core_layer`       |
| Ruff / Mypy strict / Bandit                                                    | ✅ all green                                                          |
