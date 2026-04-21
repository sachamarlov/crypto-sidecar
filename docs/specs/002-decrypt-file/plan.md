# 002 — Decrypt a `.crypt` file — technical plan

## Touched modules

- `guardiabox.core.container` — `read_header()` parses the
  versioned header introduced by spec 001.
- `guardiabox.core.kdf` — KDFs are looked up by `kdf_id`
  (`Pbkdf2Kdf` / `Argon2idKdf`) and instantiated via their
  `decode_params(blob)` classmethod.
- `guardiabox.core.crypto` — `AesGcmCipher.decrypt()` per chunk.
- `guardiabox.core.operations.decrypt_file()` — streaming
  orchestration with anti-oracle guarantees.
- `guardiabox.fileio.atomic` — output written atomically only after
  the GCM tag stream verifies.
- `guardiabox.security.audit` — entries `file.decrypt` /
  `file.decrypt_failed` appended.
- `guardiabox.ui.cli.commands.decrypt` — Typer command + `--stdout` /
  `--output` flags + exit-code mapping.

## Algorithm

```
def decrypt_file(source: Path, password: str, *, dest: Path | None,
                 to_stdout: bool = False) -> Path | None:
    safe_source = safe_path.resolve_within(source, root=source.parent.resolve())

    with safe_source.open("rb") as fp:
        header = container.read_header(fp)

        kdf_cls = KDF_REGISTRY[header.kdf_id]                  # raises UnknownKdfError
        kdf     = kdf_cls.decode_params(header.kdf_params)

        try:
            key    = kdf.derive(password.encode(), header.salt, AES_KEY_BYTES)
            cipher = AESGCM(key)
            sink   = io.BytesIO() if to_stdout else atomic.atomic_writer(dest)

            with sink:
                for index, ciphertext_chunk in enumerate(streaming.iter_chunks(fp)):
                    nonce     = derive_chunk_nonce(header.base_nonce, index)
                    plaintext = cipher.decrypt(nonce, ciphertext_chunk, associated_data=None)
                    sink.write(plaintext)

            if to_stdout:
                sys.stdout.buffer.write(sink.getvalue())
                return None
            return dest
        except InvalidTag as exc:                              # cryptography library
            raise IntegrityError(...) from None                # ANTI-ORACLE: do NOT chain
        finally:
            if isinstance(key, bytearray):
                for i in range(len(key)): key[i] = 0
```

## Anti-oracle discipline

`InvalidTag` is raised by the `cryptography` library both when the
password is wrong (key mismatch makes the tag fail) AND when the
ciphertext was tampered with. We **must not** distinguish the two in
the user-facing message or the exit code, otherwise an attacker could
use GuardiaBox itself as an oracle. The CLI maps both to exit code 2
("decryption failed") with the same opaque stderr line.

The audit log internally records the more specific
`file.decrypt_failed` with a `reason` key (set to `"wrong-password"`
or `"integrity"`) — this is **not** echoed to stdout/stderr ; it lives
in the local audit log only.

## Anti-partial-output discipline

`atomic.atomic_writer` writes to a sibling temp file. The temp file is
renamed to the final destination only after **the GCM stream tag has
verified** for every chunk. A failure mid-stream tears down the temp
file ; the user never sees a partial `.decrypt` on disk.

## Error mapping

| Raised exception             | CLI exit code   | Audit reason                   |
| ---------------------------- | --------------- | ------------------------------ |
| `InvalidContainerError`      | 65 (EX_DATAERR) | n/a                            |
| `UnsupportedVersionError`    | 65              | n/a                            |
| `UnknownKdfError`            | 65              | n/a                            |
| `IntegrityError` / wrong pwd | 2               | "wrong-password" / "integrity" |
| `PathTraversalError`         | 1               | n/a                            |
| `OSError` (disk full, perms) | 1               | n/a                            |

## Test plan

- **Unit** — decoding a malformed header / unknown `kdf_id` raises
  the right exception ; constant-time comparison verified by code
  review.
- **Property** — `decrypt(encrypt(x, p), p) == x` for arbitrary `x`
  (lengths 0, 1, chunk-1, chunk, chunk+1, large) and arbitrary
  policy-conformant `p`, both KDFs.
- **Tampering** — flip a random byte in a valid `.crypt` ; expect
  `IntegrityError` and zero output written.
- **Wrong password** — correct file + wrong password ; expect same
  generic error message, no `.decrypt` on disk.
- **Anti-oracle** — assert that the stderr produced for wrong-password
  is byte-equivalent to the stderr produced for tampered ciphertext.
- **E2E** — full CLI invocation with subprocess for both file mode
  and `--stdout` mode.
