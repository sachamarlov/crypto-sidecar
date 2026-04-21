# 002 — Decrypt a `.crypt` file — task breakdown

> Depends on spec 001 having landed (encrypt operation + container
> writer). Most building blocks (`AesGcmCipher.decrypt`,
> `Pbkdf2Kdf.derive`, `safe_path.resolve_within`,
> `atomic.atomic_writer`, `streaming.iter_chunks`) are reused as-is
> from spec 001.

- [ ] **T-002.01** — `core.kdf.KDF_REGISTRY: dict[int, type[KeyDerivation]]`
      populated with `0x01: Pbkdf2Kdf`, `0x02: Argon2idKdf` ; `decode_params`
      classmethods for both.
- [ ] **T-002.02** — `core.container.read_header()` real implementation
  - property test (round-trip arbitrary headers).
- [ ] **T-002.03** — `core.operations.decrypt_file()` streaming + anti-
      oracle exception mapping.
- [ ] **T-002.04** — `core.exceptions` adjustments: `IntegrityError`
      carries the same human message regardless of the underlying cause.
- [ ] **T-002.05** — Property tests for the encrypt→decrypt round trip
      on arbitrary inputs and both KDFs.
- [ ] **T-002.06** — Tampering tests: bit-flip the magic / kdf_id /
      salt / base_nonce / a ciphertext byte / the final tag, expect
      `InvalidContainerError` or `IntegrityError`.
- [ ] **T-002.07** — Anti-oracle test: stderr bytes must match
      exactly between wrong-password and tampered-ciphertext failure.
- [ ] **T-002.08** — `ui.cli.commands.decrypt` with `--output`,
      `--stdout`, `--password` flags + exit-code mapping.
- [ ] **T-002.09** — Audit log entries for both success and failure
      paths (with the internal `reason` key).
- [ ] **T-002.10** — Anti-partial-output integration test (kill the
      process mid-decrypt, assert no `.decrypt` file remains).

Definition of Done: every acceptance scenario from `spec.md` passes ;
coverage ≥ 95 % on the decrypt path ; bandit clean ; no observable
information difference between wrong-password and tampered-ciphertext
failures (verified by tests).
