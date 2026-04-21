# 004 — Secure deletion of plaintext files

- Status: draft (skeleton)
- Tracks: F-12 from `docs/SPEC.md`
- Depends on: spec 001 (encrypt) for the cryptographic-erase variant.

## Behaviour

The user invokes `guardiabox secure-delete <PATH> [--method overwrite-dod-3pass
| --method crypto-erase]`. The default method is auto-detected:

- HDD detected → `overwrite-dod-3pass`
- SSD detected → `crypto-erase`

For _overwrite_, the file is rewritten three times (zeros, ones, random)
followed by `unlink`. For _crypto-erase_, the file's data-encryption key is
zero-filled both in memory and in the keystore, then the ciphertext file is
unlinked.

## Acceptance criteria (Gherkin)

```gherkin
Scenario: Overwrite a file on HDD
  Given a 4 KiB file on a host advertising HDD storage
  When I run "guardiabox secure-delete <file>"
  Then the file no longer exists
  And forensic recovery from the same offsets returns only the random pass content

Scenario: Cryptographic erase on SSD
  Given an encrypted file whose key is stored in the keystore
  When I run "guardiabox secure-delete <file> --method crypto-erase"
  Then the keystore entry for the file is zeroed
  And the .crypt file is unlinked
  And subsequent attempts to decrypt yield "key not found"

Scenario: Refuse to delete outside vault root
  Given a path that resolves outside the vault root
  When I attempt secure-delete
  Then it fails with PathTraversalError without touching anything
```

## Documented limitations

- Overwrite is _best effort_ on flash media (wear-levelling, overprovisioning
  per NIST SP 800-88r2 §5.2). The CLI prints a warning when the user requests
  `overwrite-*` on a detected SSD.
- Cryptographic erase relies on the keystore's confidentiality; if the
  keystore is itself compromised, the ciphertext blocks may still be
  recoverable. Mitigation: SQLCipher (ADR-0003).

## Plan / tasks

To be drafted before implementation begins.
