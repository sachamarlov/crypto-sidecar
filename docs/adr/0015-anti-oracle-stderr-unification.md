# 0015 — Anti-oracle: unify stderr and exit code on every decrypt failure

- Status: accepted
- Date: 2026-04-24
- Deciders: @sachamarlov, Claude Opus 4.7
- Tags: [crypto, cli, threat-model]
- Supersedes: the anti-oracle approach initially delivered with spec 002 (PR #22).

## Context

Two independent external audits (security + quality) conducted in
April 2026 uncovered that spec 002's anti-oracle guarantee — "an
attacker observing the CLI cannot distinguish wrong-password from
tampered-ciphertext" — was **not** held by the shipped code:

1. **structlog leaked the exception class on stderr.** `core.operations`
   caught `DecryptionError` / `CorruptedContainerError` in the streaming
   branch and emitted `_log.warning("vault.file.decrypt_failed",
reason=type(exc).__name__)`. Because the project-wide logger is
   configured with `structlog.PrintLoggerFactory(file=sys.stderr)`, this
   event landed on **the real stderr of the process**, disclosing
   `reason=DecryptionError` vs `reason=CorruptedContainerError` vs
   `reason=IntegrityError`.

2. **`CliRunner` was blind to the leak.** The original test suite
   (`tests/unit/test_cli_anti_oracle.py`) drove the CLI through
   `typer.testing.CliRunner.invoke()`, which captures only
   `typer.echo(err=True)` and does **not** intercept writes that other
   threads / libraries make to `sys.stderr`. The test passed falsely and
   shipped a broken invariant.

3. **Exit codes already differed** between pre-KDF container parse
   failures (exit 65 / `EX_DATAERR`) and post-KDF AEAD failures (exit 2
   / `AUTH_FAILED`). That is intentional when the distinction is
   structural (magic bytes, version byte, kdf_id are public metadata —
   they cannot help an attacker narrow the password). But
   **stream-truncation** errors raised by
   `_decrypt_stream_plaintext` fell into the former class
   (`CorruptedContainerError` → exit 65) while belonging conceptually to
   the latter — an attacker who can truncate the ciphertext could thus
   distinguish that specific failure from a wrong password.

## Considered options

- **A. Drop the warning, keep CorruptedContainerError routing.** Would
  cover issue (1) but leave issue (3) — truncation still exits 65 while
  wrong-password exits 2.
- **B. Route every failure through a single exit code.** Simple and
  uniform but loses the legitimate distinction between "this isn't even
  a valid GuardiaBox container" (fast, returns 65 before touching the
  KDF — no timing oracle) and "authentication failed" (slow, after KDF
  — returns 2).
- **C. Collapse only post-header failures, retain pre-header ones**
  (chosen). `_decrypt_stream_plaintext` now raises `DecryptionError` on
  stream-level errors (truncated chunks, missing final chunk). All
  post-KDF failures map to exit 2 + the single `ANTI_ORACLE_MESSAGE`.
  Pre-KDF failures (InvalidContainer, UnsupportedVersion, UnknownKdf,
  WeakKdfParameters) remain distinct (exit 65) because they are about
  metadata that is public by construction.

## Decision

Adopt **option C**:

- `core/operations.py` no longer emits structlog warnings on decrypt
  failure. The previous events are removed entirely (no "redacted
  reason" middle ground — the event's **presence** itself was a weak
  timing oracle).
- `_decrypt_stream_plaintext` raises `DecryptionError` when the
  ciphertext stream is truncated or short-reads beneath the GCM tag —
  these are post-KDF failures and must be indistinguishable from a
  wrong password.
- `ui.cli.io.exit_for` keeps the two-tier mapping:
  - `InvalidContainerError` / `UnsupportedVersionError` /
    `UnknownKdfError` / `WeakKdfParametersError` / `CorruptedContainerError`
    (from `read_header`) → exit 65.
  - `DecryptionError` / `IntegrityError` (from the streaming decryption)
    → exit 2 with `ANTI_ORACLE_MESSAGE`.
- `tests/unit/test_cli_anti_oracle.py` is rewritten around
  `subprocess.run`, which captures the process's real `sys.stderr`.
  Assertions:
  - wrong-password and tampered-ciphertext produce **byte-identical**
    stderr after ANSI stripping;
  - the strings `DecryptionError`, `IntegrityError`,
    `CorruptedContainerError` never appear on stderr;
  - truncation exits 2, not 65.

## Consequences

**Positive**

- The anti-oracle is now infalsifiable at the test level — the real
  stderr is captured; CliRunner's blind-spot is gone.
- The structlog stderr channel is no longer observable by an attacker
  for decrypt events. When persistent audit logging lands (spec
  000-multi-user), it writes to a local append-only file, not to fd 2.
- A post-KDF truncation is indistinguishable from a wrong password,
  closing the most realistic tamper-oracle attack on the format.

**Negative**

- Debugging a real decryption failure on a user's machine loses the
  stderr hint (was it the password? was the file corrupted?). The
  `DecryptionError` `__str__` still contains the cause if the user runs
  under `--log-level=debug` or writes a Python script that catches the
  exception — we only suppress the CLI surface.
- Observability for operators is slightly degraded until
  spec 000-multi-user's audit log lands.

**Neutral**

- Tests are slower (subprocess spawn for each anti-oracle assertion ≈
  1 s). Acceptable given the criticality.

## References

- PR #22 — spec 002 initial merge (the implementation superseded here).
- PR #24 — Fix-1.A + rest of the cleanup.
- External audit reports — logged in the conversation, not committed
  to the repo (size, auditor identities redacted).
- NIST SP 800-38D §6 — AEAD failure behaviour.
- `tests/unit/test_cli_anti_oracle.py` — enforces the contract.
