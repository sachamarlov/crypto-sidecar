# 003 — RSA share — technical plan

## Touched modules

- `guardiabox.core.crypto` — `RsaWrap.wrap()` / `unwrap()`
  (RSA-OAEP-SHA256), `RsaSign.sign()` / `verify()` (RSA-PSS-SHA256).
- `guardiabox.core.share_token` — `.gbox-share` v1 binary format
  reader / writer.
- `guardiabox.core.operations.share_file()` /
  `accept_share()` — orchestration.
- `guardiabox.security.keystore` — `unwrap_rsa_private()` already
  introduced in spec 000-multi-user.
- `guardiabox.persistence.repositories.ShareRepository` — record /
  retrieve / delete share entries.
- `guardiabox.ui.cli.commands.{share,accept}` — Typer commands.

## Format `.gbox-share` v1

```
offset    bytes   field
─────────────────────────────────────────────────────────
0         4       magic = b"GBSH"
4         1       version (currently 0x01)
5         16      sender_user_id (UUIDv4)
21        16      recipient_user_id (UUIDv4)
37        32      content_sha256 (SHA-256 of the .crypt being shared)
69        2       wrapped_dek_length (uint16 BE)
71        N       wrapped_dek (RSA-OAEP-SHA256 with recipient's public key)
71+N      8       expires_at (uint64 BE, Unix epoch seconds, 0 = never)
79+N      4       permission_flags (uint32 BE; bit 0 = read, bit 1 = re-share)
83+N      *       embedded ciphertext (the .crypt file) OR reference (path)
EOF-512   512     RSA-PSS signature over all preceding bytes (sender's private key)
```

The signature is verified **before** any other action (decode, unwrap,
decrypt). Tampering at any byte invalidates the signature and the
import refuses with `IntegrityError`.

## Algorithm — sender side

```
def share_file(item: VaultItem, recipient: User, *, expires_at: datetime | None,
               can_reshare: bool, sender_keystore: Keystore, sender_pwd: str) -> Path:
    sender_priv = keystore.unwrap_rsa_private(sender_keystore, sender_pwd)
    dek         = item.dek                                # already in keystore
    wrapped_dek = rsa_wrap(dek, recipient.rsa_public_pem)
    payload     = build_payload(sender, recipient, item, wrapped_dek, expires_at, can_reshare)
    signature   = rsa_pss_sign(payload, sender_priv)
    out_path    = item.path.with_suffix(".gbox-share")
    atomic_write_bytes(out_path, payload + signature)
    audit_log.append("file.share", actor=sender.id, target=recipient.id, ...)
    return out_path
```

## Algorithm — recipient side

```
def accept_share(share_path: Path, recipient_keystore: Keystore, recipient_pwd: str) -> Path:
    raw            = share_path.read_bytes()
    payload, sig   = raw[:-512], raw[-512:]
    sender_pubkey  = user_repo.get(parse_sender_id(payload)).rsa_public_pem
    rsa_pss_verify(payload, sig, sender_pubkey)           # raises IntegrityError on tamper
    fields         = parse_payload(payload)
    if fields.expires_at and now() > fields.expires_at:
        raise ShareExpiredError
    recipient_priv = keystore.unwrap_rsa_private(recipient_keystore, recipient_pwd)
    dek            = rsa_unwrap(fields.wrapped_dek, recipient_priv)
    plaintext_path = decrypt_using_dek(fields.embedded_ciphertext, dek)
    audit_log.append("file.share_accept", actor=recipient.id, source_share=...)
    return plaintext_path
```

## Test plan

- **Unit** — RSA wrap / unwrap round trip on random 32-byte DEKs ;
  PSS sign / verify round trip on arbitrary payloads.
- **Integration** — full share between two locally-registered users
  (Alice and Bob), assert Bob's plaintext matches Alice's pre-encrypt
  bytes.
- **Tampering** — flip a payload byte, assert `IntegrityError` ; flip
  a signature byte, assert `IntegrityError` ; substitute the
  `recipient_user_id`, assert the wrap won't unwrap with anyone else's
  key.
- **Expiry** — accept a share past `expires_at`, expect
  `ShareExpiredError`.
- **Replay** — assert that re-importing the same share token does not
  silently accept twice (deduplication via `content_sha256` +
  `share_id`).
- **Property** — share token round-trip on arbitrary parameter
  combinations (permissions, expiry, payload size).

## Open questions

- Should the recipient's public key fingerprint be displayed to the
  sender for **out-of-band verification** before sending ? Yes ;
  acceptance scenario in `spec.md` will be extended in the
  implementation PR.
