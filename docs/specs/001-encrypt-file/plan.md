# 001 — Encrypt a file — technical plan

## Touched modules

* `guardiabox.core.kdf` — implement `Pbkdf2Kdf.derive`, `encode_params`,
  `decode_params`, and the analogous `Argon2idKdf` methods.
* `guardiabox.core.crypto` — implement `AesGcmCipher.encrypt` /
  `.decrypt` against `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
* `guardiabox.core.container` — implement `write_header` / `read_header`
  per the layout in `docs/ARCHITECTURE.md` § 5.
* `guardiabox.fileio.safe_path` — implement `resolve_within`.
* `guardiabox.fileio.atomic` — implement `atomic_writer`.
* `guardiabox.fileio.streaming` — implement `iter_chunks`.
* `guardiabox.security.password` — implement `evaluate` and `assert_strong`.
* `guardiabox.ui.cli.commands.encrypt` — wire `guardiabox encrypt`.

## Algorithm

```
def encrypt_file(source: Path, password: str, *, kdf: KeyDerivation, dest: Path | None) -> Path:
    target = dest or source.with_suffix(source.suffix + ".crypt")
    safe_target = safe_path.resolve_within(target, root=source.parent.resolve())

    salt = secrets.token_bytes(SALT_BYTES)
    base_nonce = secrets.token_bytes(AES_GCM_NONCE_BYTES)
    key = kdf.derive(password.encode(), salt, AES_KEY_BYTES)

    try:
        with atomic.atomic_writer(safe_target) as out:
            container.write_header(out, ContainerHeader(
                version=CONTAINER_VERSION, kdf_id=kdf.kdf_id,
                kdf_params=kdf.encode_params(),
                salt=salt, base_nonce=base_nonce,
            ))
            cipher = AESGCM(key)
            for index, chunk in enumerate(streaming.iter_chunks(source)):
                nonce = derive_chunk_nonce(base_nonce, index)
                out.write(cipher.encrypt(nonce, chunk, associated_data=None))
    finally:
        # CRITICAL: zero-fill the derived key buffer
        if isinstance(key, bytearray):
            for i in range(len(key)): key[i] = 0
    return safe_target
```

`derive_chunk_nonce` = `base_nonce[:8] || pack("!I", chunk_index)`.

## Sequence

```
CLI ──► assert_strong(password)            (raises WeakPasswordError)
    ──► safe_path.resolve_within(target)   (raises PathTraversalError)
    ──► kdf.derive(password, salt, 32)     (PBKDF2 or Argon2id)
    ──► AESGCM stream encryption per chunk
    ──► atomic_writer commits .crypt
    ──► return Path
```

## Error mapping

| Raised exception              | CLI exit code | UI message (FR)                                  |
|-------------------------------|---------------|--------------------------------------------------|
| `WeakPasswordError`           | 1             | "Mot de passe trop faible (score zxcvbn < 3)."   |
| `PathTraversalError`          | 1             | "Chemin refusé : sortie de la racine autorisée." |
| `OSError` (disk full, perms)  | 1             | "Erreur disque : <message OS>"                   |
| `KeyboardInterrupt`           | 130           | (silent — partial writes cleaned up)             |

## Test plan

* **Unit** — each module's pure functions.
* **Property** — `decrypt(encrypt(x, p, kdf), p, kdf) == x` for arbitrary
  `bytes` (length 0, 1, 1 chunk-1, 1 chunk, 1 chunk+1, 10 MiB) and arbitrary
  passwords (length ≥ 12, score ≥ 3) for both KDFs.
* **Integration** — full CLI invocation with subprocess, real tmp paths.
* **Security** — fuzz the container parser with random bytes; expect
  `InvalidContainerError`/`CorruptedContainerError`, never a crash or panic.

## Open questions

None at this point.
