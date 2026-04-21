# 003 — RSA share — task breakdown

> Depends on spec 001 (`.crypt` writer/reader) and spec 000-multi-user
> (per-user RSA keypairs in the keystore).

- [ ] **T-003.01** — `core.crypto.RsaWrap.wrap / unwrap` (RSA-OAEP-SHA256)
      with KAT vectors from RFC 8017 Appendix C.
- [ ] **T-003.02** — `core.crypto.RsaSign.sign / verify` (RSA-PSS-SHA256)
      with KAT vectors.
- [ ] **T-003.03** — `core.share_token.{write,read}` for the
      `.gbox-share` v1 binary format + property test (round-trip arbitrary
      payloads).
- [ ] **T-003.04** — `core.operations.share_file()` — sender-side
      orchestration.
- [ ] **T-003.05** — `core.operations.accept_share()` — recipient-side
      orchestration with anti-oracle on signature failure.
- [ ] **T-003.06** — `persistence.repositories.ShareRepository` (record
      / list / delete) + dedup on `content_sha256 + share_id`.
- [ ] **T-003.07** — `core.exceptions.ShareExpiredError`.
- [ ] **T-003.08** — `ui.cli.commands.share` (`--to USER`, `--expires
DAYS`, `--reshare`, `-o OUTPUT`) + E2E test.
- [ ] **T-003.09** — `ui.cli.commands.accept` (single positional path)
  - E2E test asserting both successful accept and refused tampered
    accept.
- [ ] **T-003.10** — Out-of-band fingerprint display: `share` prints
      `recipient: SHA-256 ab:cd:...` and asks `Continue? [y/N]`.

Definition of Done: every acceptance scenario from `spec.md` passes ;
coverage ≥ 95 % on `core/crypto/rsa*`, `core/share_token`, `core/
operations/share*` ; bandit clean ; integration test "Alice shares,
Bob accepts" passes against a real SQLite vault.
