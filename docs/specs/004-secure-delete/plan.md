# 004 — Secure delete — technical plan

## Touched modules

- `guardiabox.core.secure_delete` —
  `secure_delete(path, method)` dispatch on `SecureDeleteMethod`.
- `guardiabox.core.secure_delete.overwrite` — DoD 5220.22-M three-pass
  (zero / one / random).
- `guardiabox.core.secure_delete.crypto_erase` — zero-fills the
  file's data-encryption key in the keystore + unlinks the
  ciphertext.
- `guardiabox.fileio.platform` — OS-level helpers, including
  `is_ssd(path)` (Windows: `fsutil behavior query DisableDeleteNotify`
  - `SeekPenalty`; Linux: `/sys/block/<dev>/queue/rotational`; macOS:
    `diskutil info`).
- `guardiabox.security.audit` — `file.secure_delete` entries with
  `method` + `passes` keys.
- `guardiabox.ui.cli.commands.secure_delete` — Typer command with
  `--method auto|overwrite|crypto-erase` and `--passes N`.

## Algorithm — overwrite (DoD 5220.22-M)

```
def overwrite(path: Path, *, passes: int = 3) -> None:
    size = path.stat().st_size
    patterns = [b"\x00", b"\xff", os.urandom(1)]          # zero, one, random
    with path.open("r+b", buffering=0) as fp:
        for pattern in patterns[:passes]:
            fp.seek(0)
            written = 0
            while written < size:
                chunk = pattern * min(64 * 1024, size - written)
                fp.write(chunk)
                written += len(chunk)
            fp.flush()
            os.fsync(fp.fileno())
    path.unlink()
```

## Algorithm — cryptographic erase

```
def crypto_erase(item: VaultItem, vault: Vault) -> None:
    keystore_entry = vault.repo.get_dek_entry(item.id)
    zero_fill(keystore_entry.wrapped_dek)                 # in memory
    vault.repo.zero_dek_entry(item.id)                    # rewrite the row with zeros
    item.path.unlink()
```

The keystore entry being zero-filled both in memory and persisted
makes the `.crypt` file's content unrecoverable even if the bytes
remain physically on the SSD: without the DEK the AES-GCM ciphertext
is computationally indistinguishable from random.

## SSD detection (Windows path)

```
def is_ssd_windows(path: Path) -> bool | None:
    drive = path.resolve().drive  # e.g. "C:"
    out = subprocess.run(
        ["fsutil", "fsinfo", "ntfsinfo", drive],
        capture_output=True, text=True, check=False,
    ).stdout
    # NTFS exposes "Bytes Per Physical Sector" and SSD info indirectly.
    # Better: use Win32 IOCTL_STORAGE_QUERY_PROPERTY via ctypes.
    ...
```

If detection fails, default to `crypto_erase` (safer assumption since
overwrite is futile on flash media).

## CLI behaviour

```bash
# Default: auto-detect storage type, choose method accordingly
guardiabox secure-delete invoice.pdf

# Force a method
guardiabox secure-delete invoice.pdf --method overwrite --passes 7
guardiabox secure-delete invoice.pdf --method crypto-erase

# CLI prints a warning if the user requests overwrite on detected SSD
> Warning: target is on SSD. Overwrite is best-effort only on flash media.
> NIST SP 800-88r2 recommends crypto-erase. Continue anyway? [y/N]
```

## Test plan

- **Unit** — overwrite: feed a tmp file, assert it no longer exists ;
  feed an in-memory replacement that records writes, assert the
  expected pattern sequence.
- **Unit** — crypto-erase: assert the DEK row is rewritten to zeros
  and that subsequent decrypt attempts fail with `KeyNotFoundError`.
- **Integration** — full lifecycle: encrypt a file, secure-delete it
  via crypto-erase, attempt to decrypt: must fail.
- **Integration** — full lifecycle on a real `tmpfs` mount (Linux
  CI): encrypt a 1 MiB file, overwrite-delete it, run a forensic
  scan with `strings` on the device, assert the original bytes are
  no longer present.
- **Platform** — `is_ssd` correctly identifies the runner's disk on
  ubuntu-latest (likely SSD on GitHub Actions VMs) and on Windows.

## Open questions

- Use `dd` semantics or a Python implementation for the overwrite
  pass ? Pure Python so we don't add a system tool dependency.
