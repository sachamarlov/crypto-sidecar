# 001 — Encrypt a file — task breakdown

> Atomic tasks in suggested order. All delivered together in PR
> `feat/001-encrypt-file` since every sub-module is a prerequisite for a
> round-trip demo (see CLAUDE.md §9bis / memory `feedback_prod_ready_per_phase`).

- [x] **T-001.01** — `core.constants` augmented with `SALT_BYTES`,
      `KDF_PARAMS_MAX_BYTES`, and KDF parameter floors
      (`PBKDF2_MIN_ITERATIONS`, `ARGON2_MIN_*`). `derive_chunk_nonce` helper
      in `core.crypto`.
- [x] **T-001.02** — `core.crypto.AesGcmCipher.encrypt/decrypt` over
      `cryptography.hazmat`'s `AESGCM`, plus `chunk_aad` binding
      `(header, index, is_final)` to every chunk.
- [x] **T-001.03** — `core.kdf.Pbkdf2Kdf.derive/encode_params/decode_params`
      with floor enforcement at both construct and decode time.
- [x] **T-001.04** — `core.kdf.Argon2idKdf.derive/encode_params/decode_params`,
      plus the `kdf_for_id` dispatcher.
- [x] **T-001.05** — `core.container.write_header/read_header`
      (`ContainerHeader` validates magic/version/kdf/salt/nonce at
      construction) + `header_bytes()` helper exposed for AAD binding.
- [x] **T-001.06** — `fileio.safe_path.resolve_within` rejects path traversal
      AND symlinks in the non-resolved chain (fix: earlier draft followed
      symlinks before checking, which silently neutered the guard on Windows
      dev-mode).
- [x] **T-001.07** — `fileio.atomic.atomic_writer` uses `NamedTemporaryFile`
      in the target directory + fsync + `os.replace`, with best-effort POSIX
      directory fsync. Exception paths unlink the temp file.
- [x] **T-001.08** — `fileio.streaming.iter_chunks` lazy generator with a
      configurable chunk size.
- [x] **T-001.09** — `security.password.evaluate/assert_strong` wraps zxcvbn
      and enforces length ≥ 12 and score ≥ 3.
- [x] **T-001.10** — `core.operations.encrypt_file / decrypt_file /
encrypt_message / decrypt_message` stream chunks with
      `is_final`-flagged AAD. Property-based round trip over bytes of
      interesting sizes.
- [x] **T-001.11** — `ui.cli.commands.encrypt` and `ui.cli.commands.decrypt`
      (Typer) with `--password-stdin`, `--message`, `--kdf`, French error
      messages, exit codes (1 user / 2 auth / 130 SIGINT).
- [x] **T-001.12** — `docs/CHANGELOG.md` handled automatically by
      release-please from the Conventional Commit title.

## Definition of Done

| Gate                     | Status                                                                     |
| ------------------------ | -------------------------------------------------------------------------- |
| All acceptance scenarios | ✅ covered by property & integration tests                                 |
| Coverage — overall       | ✅ 94.56 % (floor 80 %)                                                    |
| Coverage — `core/`       | ✅ 100 % on operations / crypto / kdf / container / constants / exceptions |
| Coverage — `security/`   | ✅ 100 % on `security/password.py`                                         |
| Ruff                     | ✅ 0 error                                                                 |
| Mypy `--strict`          | ✅ 0 error in 60 files                                                     |
| Bandit                   | ✅ 0 issue in 1 973 LoC                                                    |
| Pre-commit all hooks     | ✅ all green                                                               |
