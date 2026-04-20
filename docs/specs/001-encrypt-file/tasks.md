# 001 — Encrypt a file — task breakdown

> Atomic tasks in suggested order. Each task ends with a green CI on a feature
> branch and is squash-merged into `main`.

- [ ] **T-001.01** — Implement `core.constants` review (no changes expected)
  and add `derive_chunk_nonce` helper in `core.crypto`.
- [ ] **T-001.02** — Implement `core.crypto.AesGcmCipher.encrypt/decrypt`
  with unit tests against KAT vectors from NIST SP 800-38D Appendix B.
- [ ] **T-001.03** — Implement `core.kdf.Pbkdf2Kdf.derive/encode_params/decode_params`
  with KAT vectors from RFC 6070.
- [ ] **T-001.04** — Implement `core.kdf.Argon2idKdf.derive/encode_params/decode_params`
  with reference vectors.
- [ ] **T-001.05** — Implement `core.container.write_header/read_header`
  with unit tests (round-trip arbitrary headers).
- [ ] **T-001.06** — Implement `fileio.safe_path.resolve_within`
  with negative tests (..//etc/passwd, symlinks, junction points on Windows).
- [ ] **T-001.07** — Implement `fileio.atomic.atomic_writer` (NamedTemporary
  in same dir + os.replace + fsync). Test against simulated SIGKILL.
- [ ] **T-001.08** — Implement `fileio.streaming.iter_chunks` (lazy generator,
  configurable size).
- [ ] **T-001.09** — Implement `security.password.evaluate/assert_strong`
  with zxcvbn integration; tests on canonical weak/strong corpora.
- [ ] **T-001.10** — Wire it all in `core.crypto.encrypt_file` (or in a
  `core/operations.py` if cleaner). Property test the round trip.
- [ ] **T-001.11** — Implement `ui.cli.commands.encrypt` (Typer command,
  prompts, error mapping, exit codes). E2E test via subprocess.
- [ ] **T-001.12** — Update `docs/CHANGELOG.md` (handled automatically by
  release-please from conventional commit messages).

Definition of Done: all acceptance criteria from `spec.md` pass; coverage
≥ 95 % on `core/`, `security/`, `fileio/`; bandit clean; `mypy --strict`
clean; PR approved and squash-merged.
