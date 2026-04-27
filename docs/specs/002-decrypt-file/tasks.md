# 002 — Decrypt a `.crypt` file — task breakdown

> Most of the building blocks landed in spec 001. This spec formalises
> the anti-oracle discipline, aligns exit codes with POSIX conventions,
> and exhaustively tests every tampering surface.

- [x] **T-002.01** — `core.kdf.KDF_REGISTRY: dict[int, type[KeyDerivation]]`
      populated with `0x01: Pbkdf2Kdf`, `0x02: Argon2idKdf`. `decode_params`
      classmethods implemented on both. `kdf_for_id` dispatches through
      the registry.
- [x] **T-002.02** — `core.container.read_header()` already real
      (spec 001). Round-trip tests in `tests/unit/test_container.py`.
- [x] **T-002.03** — `core.operations.decrypt_file()` already streaming
      with chunk-bound AAD (spec 001). Anti-oracle mapping lives in
      `ui.cli.io.exit_for`.
- [x] **T-002.04** — `core.exceptions.IntegrityError` and
      `core.exceptions.DecryptionError` both surface identical
      user-facing output via `ui.cli.io.ANTI_ORACLE_MESSAGE`.
- [x] **T-002.05** — Property tests in
      `tests/property/test_stream_roundtrip.py` (200 examples) and
      `tests/property/test_crypto_roundtrip.py` cover both KDFs.
- [x] **T-002.06** — Tampering tests: `tests/unit/test_cli_tampering.py`
      bit-flips magic, version, kdf_id, kdf_params, salt, base_nonce,
      ciphertext, tag — each offset triggers the right exit code.
- [x] **T-002.07** — Anti-oracle test: `tests/unit/test_cli_anti_oracle.py`
      asserts stderr bytes are byte-identical between wrong-password
      and tampered-ciphertext failures.
- [x] **T-002.08** — `ui.cli.commands.decrypt` with `--output`,
      `--stdout` (alias `--message`, `-m`), `--password-stdin` flags +
      exit-code mapping via `io.exit_for`.
- [x] **T-002.09** — Audit log entries for both success and failure
      paths. Implemented in Phase C-2 via the `--vault-user` opt-in
      flag on `decrypt`: when present, `ui/cli/_vault_audit.py` opens
      a vault session under the admin password and appends a
      `file.decrypt` (or `file.decrypt_failed` on `IntegrityError` /
      `DecryptionError`) entry to the hash-chained audit log. See
      `T-000mu.13` and the four integration tests in
      `tests/integration/test_cli_vault_audit_hook.py`.
- [x] **T-002.10** — Anti-partial-output integration tests:
      `tests/unit/test_anti_partial_output.py` corrupts mid-stream and
      asserts no `.decrypt` file remains.

## Definition of Done

| Gate                          | Status                                                                     |
| ----------------------------- | -------------------------------------------------------------------------- |
| All acceptance scenarios      | ✅ covered (wrong-password anti-oracle, tampered ciphertext, round-trip)   |
| Anti-oracle stderr-byte match | ✅ `test_wrong_password_and_tampered_chunk_share_exact_stderr`             |
| Anti-partial-output           | ✅ `test_no_decrypt_file_when_mid_stream_chunk_is_corrupted`               |
| Exit codes POSIX-aligned      | ✅ 0 / 1 / 2 / 3 / 64 / 65 / 130 via `ui.cli.io.ExitCode`                  |
| Coverage — overall            | ✅ 98.58 % (floor 80 %)                                                    |
| Coverage — `core/`            | ✅ 100 % on operations / crypto / kdf / container / constants / exceptions |
| Coverage — `ui/cli/io.py`     | ✅ 100 %                                                                   |
| Ruff / Mypy strict / Bandit   | ✅ all green                                                               |
