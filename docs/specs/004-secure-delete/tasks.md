# 004 — Secure delete — task breakdown

> Independent of other features beyond the keystore (spec
> 000-multi-user) for the cryptographic-erase path.

- [ ] **T-004.01** — `core.secure_delete.SecureDeleteMethod` enum +
      `secure_delete()` dispatch.
- [ ] **T-004.02** — `core.secure_delete.overwrite()` real
      implementation (zero / one / random, configurable pass count) +
      unit test on `tmp_path`.
- [ ] **T-004.03** — `core.secure_delete.crypto_erase()` real
      implementation (zero DEK in memory + persist + unlink ciphertext) +
      unit test asserting subsequent decrypt fails.
- [ ] **T-004.04** — `core.exceptions.KeyNotFoundError` (raised by
      decrypt when the DEK has been erased).
- [ ] **T-004.05** — `fileio.platform.is_ssd()` Windows
      implementation (Win32 `IOCTL_STORAGE_QUERY_PROPERTY` via ctypes).
- [ ] **T-004.06** — `fileio.platform.is_ssd()` Linux implementation
      (read `/sys/block/<dev>/queue/rotational`).
- [ ] **T-004.07** — `fileio.platform.is_ssd()` macOS implementation
      (parse `diskutil info`).
- [ ] **T-004.08** — `ui.cli.commands.secure_delete` Typer command with
      `--method auto|overwrite|crypto-erase` and `--passes`.
- [ ] **T-004.09** — Confirmation prompt when user requests
      `overwrite` on detected SSD ; `--no-confirm` to bypass.
- [ ] **T-004.10** — Audit log entry `file.secure_delete` with
      `method`, `passes`, `actor_user_id`, `target` (filename hash).
- [ ] **T-004.11** — Forensic recovery integration test on Linux
      `tmpfs` (`strings` over the raw device should not contain the
      original bytes after overwrite).
- [ ] **T-004.12** — Doctor command extension `guardiabox doctor
--report-ssd` (lists each known media + reports overwrite
      effectiveness expectation).

Definition of Done: every acceptance scenario from `spec.md` passes ;
coverage ≥ 95 % on `core/secure_delete/`, `fileio/platform.py` ;
bandit clean ; the forensic integration test runs on the Linux CI
runner.
