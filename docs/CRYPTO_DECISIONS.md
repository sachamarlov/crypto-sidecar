# CRYPTO DECISIONS — Justifications and parameters

> Every cryptographic choice with the source backing it. Update on parameter
> changes (which always require a corresponding ADR and a `.crypt` version
> bump).

## 1. Symmetric encryption — **AES-256-GCM**

* **Algorithm**: AES-GCM (NIST FIPS 197 + NIST SP 800-38D).
* **Key size**: 256 bits.
* **Nonce**: 12 random bytes per chunk, derived from a base nonce + chunk
  counter (`base_nonce[:8] || counter_be32`). NIST SP 800-38D recommends 12-byte
  nonces for performance and security.
* **Tag**: 128 bits (the GCM default).

### Why GCM over CBC / CTR + HMAC

GCM is an authenticated encryption with associated data (AEAD) primitive
defined in NIST SP 800-38D. It bundles confidentiality and integrity into a
single pass and is hardware-accelerated on every modern CPU (AES-NI + CLMUL).
CBC + HMAC requires two passes and is fragile to padding-oracle attacks if
implemented incorrectly.

### Why per-chunk nonces (and not one nonce per file)

GCM is catastrophically broken under nonce reuse with the same key. Streaming a
multi-GiB file in 64 KiB chunks means ~16 384 chunks per GiB; with a fresh
nonce per chunk and a per-file random base nonce, the probability of collision
remains negligible (`2^-96` collision space, even ignoring per-file salt).

### Why not GCM-SIV or XChaCha20-Poly1305

GCM-SIV (RFC 8452) tolerates accidental nonce reuse but is **not** in the
`cryptography` library's stable API (sits under `hazmat` and is less
hardware-accelerated). XChaCha20-Poly1305 is excellent (RFC 8439 base) but
the academic brief explicitly mentions AES-GCM. We stay with the brief.

* **Sources**:
  * NIST SP 800-38D — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
  * RFC 5116 (AEAD interface) — https://www.rfc-editor.org/rfc/rfc5116
  * `cryptography` AESGCM docs — https://cryptography.io/en/latest/hazmat/primitives/aead/

## 2. Key derivation — **PBKDF2-HMAC-SHA256** (default) and **Argon2id** (opt-in)

### PBKDF2 parameters

| Parameter        | Value         | Source                                         |
|------------------|---------------|------------------------------------------------|
| Hash             | HMAC-SHA-256  | NIST SP 800-132                                |
| Iterations       | **600 000**   | OWASP Password Storage Cheat Sheet 2026 (FIPS) |
| Salt             | 16 random B   | NIST SP 800-132 §5.1 (≥ 128-bit)               |
| Derived key size | 32 bytes      | matches AES-256                                |

### Argon2id parameters

| Parameter        | Value         | Source                                         |
|------------------|---------------|------------------------------------------------|
| Memory cost      | 64 MiB        | OWASP Password Storage Cheat Sheet 2026         |
| Time cost (t)    | 3             | OWASP                                           |
| Parallelism (p)  | 1             | OWASP                                           |
| Salt             | 16 random B   | RFC 9106                                        |
| Derived key size | 32 bytes      | matches AES-256                                 |

### Why both?

The CDC mandates PBKDF2 — we comply. We additionally expose Argon2id behind a
flag because:

* PBKDF2-SHA256 is **not memory-hard**: GPUs can crack 8-character passwords
  for ≈ \$5 000. Argon2id raises that to ≈ \$500 000 (≈ 100× harder).
* Argon2id is the OWASP **default recommendation for new systems** in 2026
  (PBKDF2 only when FIPS-140 compliance is mandatory).

The KDF used is encoded in the `.crypt` header (1 byte) — backward-compatible
migration is supported file by file.

* **Sources**:
  * OWASP Password Storage CS — https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
  * NIST SP 800-132 — https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf
  * RFC 9106 (Argon2) — https://www.rfc-editor.org/rfc/rfc9106
  * Comparative analysis — https://guptadeepak.com/research/password-hashing-guide-2026/

## 3. Asymmetric — **RSA-OAEP** for hybrid sharing

* **Algorithm**: RSA-OAEP-SHA256.
* **Key size**: 4096 bits (defensive against future advances; RSA-3072
  remains acceptable per NIST SP 800-57 Part 1 Rev 5).
* **Use**: wrap a per-share AES-256 key (the data-encryption key, DEK). The
  DEK encrypts the file content; the wrapped DEK travels in the share token.
* **Why not ECC** (e.g. X25519 + ECIES)? ECC is faster and shorter, but the
  CDC mentions RSA explicitly and PyPI has mature Python bindings.
  Migration to a hybrid X25519 / ML-KEM scheme is tracked in the ADR backlog.

* **Source**: PKCS #1 v2.2 (RFC 8017) — https://www.rfc-editor.org/rfc/rfc8017

## 4. Constant-time comparisons

Tag and HMAC comparisons go through `hmac.compare_digest`. Never use `==`.
The `cryptography` library already uses constant-time comparisons internally
for GCM tags, but our code adds defence in depth for any user-facing equality
check involving secrets.

* **Source**: Python `hmac.compare_digest` docs — https://docs.python.org/3/library/hmac.html#hmac.compare_digest

## 5. Random number generation

* All randomness uses `secrets` (Python stdlib), which proxies to the OS CSPRNG
  (`getrandom(2)` / `CryptGenRandom`).
* Never `random.*` — that module is not cryptographically secure.

## 6. Database encryption at rest — **SQLCipher**

* AES-256-CBC with HMAC-SHA512 page authentication (SQLCipher 4 default).
* Key derived from a vault administrator password via PBKDF2 with the same
  iteration count as user keystores.
* Even though file metadata is not "secret" in the strict sense, defense in
  depth dictates encrypting it (filenames can leak intent).

* **Source**: SQLCipher design — https://www.zetetic.net/sqlcipher/design/

## 7. Secure deletion

* **HDD**: 3-pass overwrite per DoD 5220.22-M (zero, one, random) followed by
  `unlink`. Effective on spinning rust.
* **SSD**: cryptographic erase. The file's data-encryption key is destroyed
  (zero-filled in memory and overwritten in the keystore), making the
  ciphertext computationally unrecoverable. The container file itself is then
  unlinked. NIST SP 800-88r2 endorses this approach because wear-levelling
  defeats overwrite on flash media.
* The user picks the strategy at the API; the GUI auto-detects HDD vs SSD via
  the OS (`fsutil` on Windows) and recommends the appropriate one.

* **Source**: NIST SP 800-88 Rev 2 — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r2.pdf

## 8. Cryptographic agility — version policy

* The `.crypt` container carries an explicit `version` byte and a `kdf_id`
  byte. Decryption code reads the version and dispatches accordingly.
* Adding a new algorithm = new KDF id + new ADR + bumped version, with a
  migration path documented in `docs/specs/`.
* Removing an algorithm = a deprecation cycle of at least one minor version
  with a CLI command to re-encrypt files into the new format.

## 9. What we explicitly do NOT do

* No homemade crypto, no "encryption-with-XOR-and-a-secret", no roll-our-own
  random.
* No "encrypt then base64 then encrypt again" chains — every layer is a place
  to introduce a bug.
* No password storage anywhere on disk in any form.
* No "remember this password for 30 days" feature.
* No fallback to weaker parameters (e.g. PBKDF2 < 600 000 iterations) — the
  enforced minimum is hard-coded in `core/constants.py`.
