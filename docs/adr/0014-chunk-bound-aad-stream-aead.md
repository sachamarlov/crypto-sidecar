# 0014 — Chunk-bound AAD for streaming AEAD

- Status: accepted
- Date: 2026-04-21
- Deciders: @sachamarlov, Claude Opus 4.7
- Tags: [crypto, format, streaming, threat-model]
- Related: ADR-0002 (dual KDF), ADR-0013 (.crypt container v1)

## Context and problem statement

`.crypt` files can be arbitrarily large (multi-GiB), so decryption must be
streaming: we read and verify one chunk at a time rather than loading the
whole file into memory. But plain AES-GCM is a one-shot AEAD: each chunk's
authentication tag only covers that chunk's own plaintext. Three attacks
follow naturally from a naive chunk-per-AEAD split:

1. **Truncation.** An attacker drops the last N chunks. Every remaining
   chunk verifies individually; the decoder has no way to tell the file is
   incomplete.
2. **Reordering.** An attacker swaps two chunks. Same problem — every chunk
   is valid under its own tag.
3. **Header substitution.** An attacker swaps the header of file A onto the
   ciphertext stream of file B that used the same password. The KDF derives
   the same key; the chunks verify; the user reads content they never
   encrypted under that name.

Plain AES-GCM's associated-data input is the lever we have against all
three. The question is: what exactly goes in there?

## Considered options

- **A. Empty AAD.** Simplest. Leaves the three attacks above open.
- **B. Per-chunk index as AAD** (`pack("!I", index)`). Prevents reordering
  but not truncation or header swap. The last chunk at index `N` still
  verifies after dropping chunks `N+1..`.
- **C. Per-chunk index + is_final flag as AAD** (`pack("!IB", index,
is_final)`). Closes truncation (the decoder **must** see an `is_final=1`
  chunk or raise). Leaves header swap open.
- **D. Per-chunk index + is_final + full header bytes as AAD** (chosen).
  Closes all three attacks.
- **E. Tink STREAM construction** (RFC-draft-like, NIST SP 800-38G framing).
  Equivalent security properties to option D, but requires implementing
  counter-based nonce derivation with an explicit "last-block bit" in the
  nonce itself rather than in the AAD. More delicate to implement correctly.

## Decision

Adopt **option D**. The associated-data blob for every chunk is:

```
AAD = header_bytes || struct.pack("!IB", chunk_index, is_final)
```

where:

- `header_bytes` is the full serialised header (see ADR-0013) — 40 bytes
  for PBKDF2, 48 for Argon2id.
- `chunk_index` is the 0-indexed position of the chunk, big-endian `uint32`.
- `is_final` is `0` for every chunk except the last, which is `1`.

Encoding uses a one-chunk lookahead so the final chunk is always flagged
correctly. Empty plaintexts emit a single empty chunk with `is_final=1`, so
the decoder always has a terminator to verify.

### Nonce derivation (separate from AAD)

The 12-byte per-chunk nonce is independent of the AAD:

```
nonce = base_nonce[:8] || struct.pack("!I", chunk_index)
```

The 64 random bits of `base_nonce[:8]` keep inter-file collisions
negligible (the per-file salt ensures the **key** is different anyway, so
even a nonce collision is survivable — we defend in depth). The 32-bit
counter gives 4 × 10⁹ chunks per file, which at the default 64 KiB chunk
size bounds a single file to ~256 TiB.

## Consequences

**Positive**

- Truncation, reordering, and header substitution are authenticated
  failures, not silent ones.
- The design is explicit and greppable: the AAD construction sits in
  `core.crypto.chunk_aad()` and is covered by unit tests asserting that
  flipping any of the three inputs changes the blob.
- No new primitive — we stay within pyca/cryptography's stable `AESGCM`
  API.

**Negative**

- Every chunk AAD includes the full header (~40-48 bytes). For a 1 GiB
  file at 64 KiB chunks that is ~800 KiB of AAD processed total — trivial
  with AES-NI but non-zero.
- The `is_final` flag makes encoding path-dependent: the encoder must know
  when it has emitted the last chunk. The one-chunk lookahead in
  `_encrypt_stream` handles this, but any future alternate encoder (e.g.
  a concurrent one) must preserve the invariant.

**Neutral**

- The AAD is not stored on disk — it is rebuilt deterministically on
  decryption from the header and chunk index. No extra storage cost.
- We do **not** additionally hash the header into the AAD: the full
  header bytes go in as-is. Hashing would save a few tens of bytes per
  chunk but introduces an extra primitive with no security gain.

## Threat-model coverage

| STRIDE          | Before (option A)       | After (option D)                         |
| --------------- | ----------------------- | ---------------------------------------- |
| Spoofing        | header swap ok          | header change → tag mismatch             |
| Tampering       | single-chunk only       | every chunk + ordering + count           |
| Repudiation     | n/a                     | n/a                                      |
| Info disclosure | n/a                     | n/a                                      |
| DoS             | small chunk loss silent | truncation surfaces as `DecryptionError` |
| Elevation       | n/a                     | n/a                                      |

## References

- Google Tink StreamAEAD — <https://github.com/tink-crypto/tink/blob/main/docs/PRIMITIVES.md#streaming-authenticated-encryption-with-associated-data>
- `age` file format v1 — <https://age-encryption.org/v1>
- NIST SP 800-38D (GCM) — <https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf>
- RFC 5116 (AEAD interface) — <https://www.rfc-editor.org/rfc/rfc5116>
- Kelsey, Schneier, Hall, Wagner — "Cryptanalytic attacks on pseudorandom
  number generators" (truncation / reordering references)
- ADR-0002, ADR-0013
- Implementation — `src/guardiabox/core/crypto.py::chunk_aad`,
  `src/guardiabox/core/operations.py::_encrypt_stream`
