# Security Policy

## Supported versions

GuardiaBox is in early development (pre-1.0). Only the `main` branch receives
security fixes. There is no support window for older snapshots.

| Version | Supported |
|---------|-----------|
| `main`  | ✅        |
| < 1.0   | ❌        |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report responsibly via one of the following channels:

- **GitHub Security Advisory** (preferred):
  https://github.com/sachamarlov/crypto-sidecar/security/advisories/new
- **Email**: contact the repository owner via their GitHub profile.

When reporting, please include:

- A clear description of the vulnerability and its impact.
- Steps to reproduce (proof-of-concept welcome).
- The affected commit SHA or version.
- Your assessment of severity (CVSS v4 if possible).
- Any suggested mitigations.

## Response timeline

- **Acknowledgment**: within 72 hours.
- **Initial assessment**: within 7 days.
- **Fix and disclosure**: coordinated with the reporter; default 90-day
  disclosure window.

## Scope

The following are **in scope** for vulnerability reports:

- Cryptographic flaws in `core/crypto/`, `security/`, or the `.crypt`
  container format.
- Authentication or authorization bypasses.
- Path traversal, command injection, deserialization vulnerabilities.
- Memory disclosure of secrets (passwords, keys, vault contents).
- Tauri sandbox escape or sidecar IPC abuse.
- Side-channel attacks demonstrably exploitable on consumer hardware
  (timing, cache).

The following are **out of scope**:

- Vulnerabilities in third-party dependencies already disclosed upstream
  (please report directly to the maintainer of the dependency).
- Issues requiring root / administrative access on the user's machine
  (the threat model assumes a non-compromised host OS).
- Cold-boot attacks, evil-maid attacks, hardware-level attacks
  (mitigation is OS-level: BitLocker, FileVault, dm-crypt).
- Theoretical weaknesses without a demonstrable attack.

## Threat model

The full threat model (STRIDE) is documented in
[`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md). Familiarity with it before
reporting will help us assess your finding.

## Recognition

Reporters of valid security vulnerabilities will be credited in the security
advisory and `CHANGELOG.md` (unless they request anonymity).

## Cryptographic policy

GuardiaBox follows current best practices as of 2026:

- AES-GCM (NIST SP 800-38D) with 12-byte nonces.
- PBKDF2-HMAC-SHA256 with ≥ 600 000 iterations (OWASP FIPS-140).
- Argon2id with m=64 MiB, t=3, p=1 (OWASP 2026).
- RSA-OAEP-SHA256 with 4096-bit keys for hybrid asymmetric sharing.
- HMAC-SHA256 with `hmac.compare_digest` for all tag comparisons.

Any deviation requires an ADR under `docs/adr/` and a corresponding update
to `docs/CRYPTO_DECISIONS.md`.
