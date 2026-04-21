# 0004 — RSA-OAEP-SHA256 hybrid cryptosystem for sharing

- Status: accepted
- Date: 2026-04-20
- Deciders: @sachamarlov, Claude Opus 4.7
- Tags: [crypto, sharing]

## Context

Users on the same machine can share an encrypted file with one another
without ever revealing their respective master passwords. We need an
asymmetric primitive that is well-supported in Python and acceptable to the
academic evaluator.

## Considered options

- **A. RSA-OAEP-SHA256, 4096-bit keys** — wraps a per-share AES-256
  data-encryption key (DEK). Mainstream, mentioned in the CDC.
- **B. X25519 + ECIES** — smaller keys, faster, modern, but the CDC
  explicitly mentions RSA. Migration tracked separately.
- **C. ML-KEM (post-quantum)** — future-proof but library churn in 2026 is
  still high; leave as a future ADR.

## Decision

Adopt **option A** for v1. The flow:

1. Sender generates a fresh AES-256 key (DEK).
2. Sender encrypts the file content (AES-GCM, fresh nonce).
3. Sender wraps the DEK with the recipient's public RSA-OAEP key.
4. Sender signs the resulting `.gbox-share` token with their own RSA private
   key (RSA-PSS-SHA256).
5. Recipient verifies the signature, unwraps the DEK with their private
   key, and decrypts the file.

## Consequences

**Positive**

- Familiar primitive — easy to defend in the oral evaluation.
- Hybrid scheme is the textbook approach (see RFC 5990).
- Forward-compatible — the share token format will carry an algorithm tag,
  so we can add X25519 / ML-KEM later without breaking v1.

**Negative**

- RSA-4096 key generation is slow (~1 s on a laptop) — done once per user,
  acceptable.
- Larger ciphertext for the wrapped key (~512 bytes) compared with ECC-based
  alternatives.

## References

- PKCS #1 v2.2 (RFC 8017) — https://www.rfc-editor.org/rfc/rfc8017
- NIST SP 800-57 Pt 1 Rev 5 (key sizes) — https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57pt1r5.pdf
