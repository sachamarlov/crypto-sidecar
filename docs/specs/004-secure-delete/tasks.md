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
- [ ] **T-004.03** — _Deferred to Phase B2_: `core.secure_delete.crypto_erase()`
      needs the keystore surface from spec 000-multi-user.
- [ ] **T-004.04** — _Deferred to Phase B2_: `core.exceptions.KeyNotFoundError`
      ships with the keystore (spec 000-multi-user).
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
- [ ] **T-004.10** — _Deferred to Phase B2_: audit log entry
      `file.secure_delete` requires the persistent audit repository.
- [ ] **T-004.11** — _Deferred to Phase B2_: the forensic Linux-tmpfs
      integration test needs a dedicated CI job (large payload, long
      runtime) and is scheduled with the crypto-erase PR so both
      end-to-end flows are validated at once.
- [ ] **T-004.12** — _Deferred to Phase E (spec 000-cli)_:
      `guardiabox doctor --report-ssd` belongs with the doctor command
      that ships with the full CLI spec.

## Phase B2 — crypto-erase (after spec 000-multi-user)

Items T-004.03 / T-004.04 / T-004.10 / T-004.11 listed above land
together in a follow-up PR once the keystore and audit repository are
in place.

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
