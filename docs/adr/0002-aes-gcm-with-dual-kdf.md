# 0002 — AES-GCM with dual KDF (PBKDF2 default, Argon2id opt-in)

- Status: accepted
- Date: 2026-04-20
- Deciders: @sachamarlov, Claude Opus 4.7
- Tags: [crypto, format]

## Context and problem statement

The CDC mandates AES-GCM and PBKDF2. OWASP 2026 strongly recommends Argon2id
for new systems because PBKDF2 is not memory-hard (a GPU can crack 8-char
passwords for ≈ \$5 000 vs ≈ \$500 000 with Argon2id).

We must comply with the CDC while also offering the best available algorithm
to security-aware users.

## Considered options

- **A. PBKDF2 only** (strict CDC). Simple, but leaves the user defenceless
  against modern GPU farms.
- **B. PBKDF2 default + Argon2id opt-in**, both selectable via flag, encoded
  in the container header.
- **C. Argon2id default + PBKDF2 fallback** for FIPS scenarios. Risks the
  evaluator concluding the CDC's PBKDF2 instruction was ignored.

## Decision

Adopt **option B**. The container's 1-byte `kdf_id` field selects between
PBKDF2 (`0x01`, default) and Argon2id (`0x02`). The chosen KDF is independent
per file, so users can migrate file-by-file.

Mandatory parameter floors enforced in `core/constants.py`:

- PBKDF2-HMAC-SHA256 ≥ 600 000 iterations (OWASP FIPS-140).
- Argon2id m ≥ 64 MiB, t ≥ 3, p ≥ 1 (OWASP 2026).

## Consequences

**Positive**

- Strict CDC compliance (PBKDF2 is the default).
- Future-proof — the file format already accommodates new KDFs by allocating
  new `kdf_id` bytes.
- Per-file migration path: re-encrypt with `--kdf argon2id` to upgrade.

**Negative**

- Slight container complexity (one byte + variable-length params blob).
- Dual implementation must be tested for both algorithms (mitigated by
  property-based tests covering both branches).

## References

- OWASP Password Storage CS — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- RFC 9106 (Argon2) — https://www.rfc-editor.org/rfc/rfc9106
- NIST SP 800-132 (PBKDF2) — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
