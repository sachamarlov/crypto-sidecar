# 0013 — `.crypt` container v1 on-disk format

- Status: accepted
- Date: 2026-04-21
- Deciders: @sachamarlov, Claude Opus 4.7
- Tags: [crypto, format, forward-compatibility]
- Supersedes / Superseded by: none
- Related: ADR-0002 (dual KDF), ADR-0014 (chunk-bound AAD)

## Context and problem statement

Spec 001 ships the first concrete `.crypt` layout. Every byte of the file is
security-relevant: the header feeds the chunk AAD (ADR-0014), the salt and
nonce drive key uniqueness, and the KDF parameters decide how much effort an
attacker must expend per guess.

Without an authoritative document for v1, any future change — even a benign
reordering — risks silently breaking users' archives. The format must also be
self-describing enough to survive evolution: new KDFs, new AEAD primitives,
new chunk sizes.

We need an ADR that (a) fixes the exact v1 layout, (b) specifies each field's
invariants, (c) lists the acceptable version-bump triggers, and (d) defines
the migration contract.

## Considered options

- **A. Fixed header, no length prefixes.** Every field at a hard-coded offset.
  Simpler reader, but impossible to grow KDF parameters or add fields without
  bumping `version`.
- **B. Length-prefixed TLV for every field.** Maximal flexibility, at the cost
  of a larger parser surface and more room for truncation mistakes.
- **C. Fixed prefix + length-prefixed KDF params only** (chosen). Everything
  that is constant-sized (magic, version, kdf_id, salt, nonce) is placed at
  known offsets; the only variable-length field (KDF params) carries a
  big-endian `uint16` length prefix. A hard ceiling (`KDF_PARAMS_MAX_BYTES =
4096`) caps adversarial header bloat.

## Decision

Adopt **option C**. The on-disk layout of a v1 `.crypt` file is:

```
offset  size       field                              invariant
------  ---------  ---------------------------------  ---------------------
0       4          magic = b"GBOX"                    must equal CONTAINER_MAGIC
4       1          version = 0x01                     must equal CONTAINER_VERSION
5       1          kdf_id                             0x01=PBKDF2, 0x02=Argon2id
6       2          kdf_params_len (uint16 big-endian) ≤ KDF_PARAMS_MAX_BYTES (4 KiB)
8       N          kdf_params (KDF-specific TLV)      PBKDF2=4B, Argon2id=12B
8+N     16         salt                               SALT_BYTES (≥ 128-bit, NIST SP 800-132)
24+N    12         base_nonce                         AES_GCM_NONCE_BYTES (NIST SP 800-38D)
36+N    *          ciphertext chunk stream            see ADR-0014
```

Per-KDF parameter layout:

```
PBKDF2-HMAC-SHA256        Argon2id
------------------------  --------------------------------------
iterations (uint32 BE)    memory_cost_kib (uint32 BE)
                          time_cost (uint32 BE)
                          parallelism (uint32 BE)
```

Parameter floors (rejected at both encode and decode, cf. ADR-0002):

- PBKDF2: iterations ≥ 600 000
- Argon2id: m ≥ 64 MiB, t ≥ 3, p ≥ 1

### What triggers a `version` bump

A bump is **required** whenever any of the following change:

1. A byte shift in the header layout (fields reordered, added, or removed).
2. A change in a fixed-size field's width (e.g. salt grows to 32 bytes).
3. A change in the ciphertext stream framing (cf. ADR-0014).
4. A new authenticated-encryption primitive replacing AES-GCM.
5. A change to the meaning of an existing `kdf_id` value.

A bump is **not** required for:

- Adding a new `kdf_id`. The reader dispatches by id and emits
  `UnknownKdfError` for unsupported values. This is the Open/Closed point of
  extension.
- Tightening parameter floors (e.g. PBKDF2 iterations → 1 000 000). Older
  files remain decryptable until the floor overtakes the stored parameters,
  at which point `WeakKdfParametersError` surfaces and a re-encrypt migration
  path is documented.

### Migration contract

- Readers **must** reject any file whose magic, version, or kdf_id does not
  match what the build supports, without attempting to heal the stream.
- Writers **must** always emit the current `CONTAINER_VERSION`.
- A future v2 reader **must** still decrypt v1 files. A v1 reader **must
  refuse** v2 files with `UnsupportedVersionError`. In other words:
  forward-compatibility is one-way.

## Consequences

**Positive**

- Binary is small and trivially parsed: 40 bytes header for PBKDF2, 48 bytes
  for Argon2id.
- Adding a third KDF is a one-byte extension of `kdf_id` and a new
  implementation of `KeyDerivation`. No header bump.
- The 4 KiB cap on `kdf_params_len` neutralises "ZIP bomb"-style abuse of
  the length prefix.
- Invariants are enforced in `ContainerHeader.__post_init__`, so no code path
  can hold a structurally invalid header.

**Negative**

- The fixed-offset prefix means any new constant-sized metadata (e.g. an
  optional header MAC) requires a version bump.
- `kdf_params` is KDF-specific: the container alone is not introspectable
  without knowing the KDF. Partially mitigated by the `inspect` CLI command
  which decodes per-KDF (cf. spec 001 follow-up).

**Neutral**

- The 8-byte fixed prefix (magic + version + kdf_id + params_len) leaves no
  room for additional flags. A future v2 reader can repurpose the currently
  unused upper bits of `version` if byte-packing pressure warrants it.

## References

- NIST SP 800-38D (GCM) — <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>
- NIST SP 800-132 (PBKDF2) — <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf>
- RFC 9106 (Argon2) — <https://www.rfc-editor.org/rfc/rfc9106>
- OWASP Password Storage Cheat Sheet — <https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html>
- ADR-0002 — `docs/adr/0002-aes-gcm-with-dual-kdf.md`
- ADR-0014 — `docs/adr/0014-chunk-bound-aad-stream-aead.md`
- Implementation — `src/guardiabox/core/container.py`, `src/guardiabox/core/constants.py`
