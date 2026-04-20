# CONVENTIONS — Code style and engineering principles

> Reference for human and AI contributors. Treat these as **tensions to
> manage** (Robert C. Martin, 2024 nuance), not as commandments.

## 1. SOLID — applied to GuardiaBox

| Principle                 | Concrete application here                                                                              |
|---------------------------|--------------------------------------------------------------------------------------------------------|
| **S**ingle Responsibility | `Pbkdf2Kdf` derives keys; `AesGcmCipher` encrypts; `Container` (de)serialises. None overlap.           |
| **O**pen / Closed         | New KDFs implement `KeyDerivation` Protocol. Existing classes are never modified, only extended.       |
| **L**iskov Substitution   | Any `KeyDerivation` is interchangeable; tests verify the contract for every implementation.            |
| **I**nterface Segregation | Distinct Protocols for `KeyDerivation`, `AeadCipher`, `UserRepository`. Clients never accept God objects. |
| **D**ependency Inversion  | `VaultService` depends on Protocols, not on SQLAlchemy or pyca's `cryptography`.                      |

## 2. DRY — Don't Repeat Yourself, with the Rule of Three

* Duplicate freely the **first two times** a pattern appears. Extract on the
  **third** occurrence, when the abstraction is informed by reality.
* The container format magic, KDF parameters, and protocol versions are
  defined in `core/constants.py` — exactly **one** source of truth.

## 3. KISS — economy of abstraction

The literal "Keep It Simple, Stupid" maxim is replaced here by **economy of
abstraction**: prefer three readable lines over an abstraction that saves one.
A design pattern is a tax on the next reader; spend it only when the gain
clearly outweighs the cost.

## 4. YAGNI — You Aren't Gonna Need It

* No feature without a `docs/specs/` entry.
* No "configurable hook just in case" until the second caller materialises.
* No backwards-compatibility shim for code that never shipped.

## 5. Composition over inheritance

Inheritance is reserved for genuine *is-a* relationships (e.g. SQLAlchemy
`Base` → models). Behaviour reuse is achieved by composition — pass
collaborators in the constructor, not via subclass hooks.

## 6. Tell, Don't Ask

```python
# Good
vault.encrypt(file, password)

# Bad
if vault.is_unlocked() and not vault.has_pending_writes():
    file.encrypt_with(vault.get_key())
```

The first form keeps invariants inside the object that owns them; the second
leaks them to every caller.

## 7. Hexagonal architecture (Ports & Adapters)

```
            ┌──────────────────────────────────┐
            │     UI adapters (CLI/TUI/GUI)    │
            └─────────────────┬────────────────┘
                              │ depends on Protocols defined in core
            ┌─────────────────▼────────────────┐
            │           core (domain)          │
            │   pure logic, no I/O imports     │
            └─────────────────┬────────────────┘
                              │ depends on Protocols defined in core
            ┌─────────────────▼────────────────┐
            │ Persistence + fileio adapters    │
            └──────────────────────────────────┘
```

* `core/` knows nothing about SQLAlchemy, FastAPI, Typer, or Tauri.
* Adapters depend inward; there is **no** circular dependency.

## 8. Type strictness

* Python: `mypy --strict` (or `ty check` once stable). No `Any` without a
  one-line comment justifying it.
* TypeScript: `strict: true`, `noUncheckedIndexedAccess: true`,
  `exactOptionalPropertyTypes: true`.
* Rust (Tauri shell): `cargo clippy --all-targets -- -D warnings`.

## 9. Naming

| Kind           | Style           | Example                    |
|----------------|-----------------|----------------------------|
| Module         | `snake_case`    | `safe_path`                |
| Function       | `snake_case`    | `derive_key()`             |
| Class          | `PascalCase`    | `Pbkdf2Kdf`                |
| Constant       | `UPPER_SNAKE`   | `AES_GCM_NONCE_BYTES`      |
| Type alias     | `PascalCase`    | `KeyBytes = bytes`         |
| Enum member    | `UPPER_SNAKE`   | `AuditAction.FILE_ENCRYPT` |
| TS component   | `PascalCase`    | `<EncryptDialog />`        |
| TS hook        | `useCamelCase`  | `useEncryptionStatus()`    |

## 10. Comments and docstrings

* Default to **no comment**.
* Document *why*, not *what*: the code already says what.
* Public functions get a Google-style docstring with `Args`, `Returns`,
  `Raises`. Internal helpers may omit it if their name is self-explanatory.
* Never leave commented-out code in a commit. Use `git` for history.

## 11. Error handling

* **Fail fast, fail loud at boundaries** — validate inputs at UI/API edges,
  trust internal callers.
* No bare `except:` or `except Exception:` without a re-raise or a logged
  context. Use the dedicated exception hierarchy in `core/exceptions.py`.
* Never swallow a security error.

## 12. Logging

* Always `structlog`, never `print` (except CLI user output via `typer.echo`).
* Levels: `DEBUG` (developer), `INFO` (lifecycle), `WARNING` (recoverable),
  `ERROR` (degraded), `CRITICAL` (unrecoverable, terminate).
* The `_redact_secrets` processor scrubs known sensitive keys; do not rely
  on it as a substitute for not logging secrets in the first place.

## 13. Testing

* Unit tests sit next to the boundary they exercise (`tests/unit/<module>`).
* Property-based tests live in `tests/property/`. Crypto roundtrips
  (`decrypt(encrypt(x)) == x`) are mandatory there.
* Integration tests use a real SQLite (no DB mocking) and a temp directory.
* End-to-end tests drive the Tauri app via Playwright.
* Coverage target: **≥ 80 % overall, ≥ 95 % on `core/` and `security/`**.

## 14. Git hygiene

* Conventional Commits with optional scope: `feat(security): …`.
* Branches named after the change: `feat/argon2-kdf`, `fix/path-traversal`.
* PRs are squash-merged into `main`; the squash title becomes the changelog
  entry via `release-please`.
* `Co-Authored-By:` trailer for every AI-assisted commit.

## 15. Documentation hygiene

* Every architectural decision → an ADR (`docs/adr/`, MADR v4).
* Every new feature → a spec (`docs/specs/`, Spec-Driven Dev).
* Markdown is wrapped at 100 columns; tables stay readable in plain text.
* Diagrams: ASCII art preferred (zero dependency); `mermaid` accepted for
  large flows.

## 16. Forbidden patterns (will block a PR)

* ❌ `import *` from anything.
* ❌ Mutable default arguments (`def f(x=[])`).
* ❌ Catching `BaseException`.
* ❌ `assert` statements outside tests (they get stripped under `-O`).
* ❌ `eval`, `exec`, `compile` on user input.
* ❌ String concatenation for SQL (use bound parameters).
* ❌ Path traversal via `os.path.join` of user input (use `safe_path`).
* ❌ Crypto code in UI layers.
* ❌ Network calls in `core/`.
* ❌ Disabling a pre-commit hook to "ship faster".

## 17. When in doubt

Ask: *"if a contributor reads this in six months without context, will they
guess what I meant?"* — if no, refactor or document.
