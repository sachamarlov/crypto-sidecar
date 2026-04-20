# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

This file is automatically maintained by
[release-please](https://github.com/googleapis/release-please) on tagged releases.
Direct edits should be limited to fixing typos.

## [Unreleased]

### Added
- Initial repository scaffolding with Tauri 2 + React 19 + Python sidecar.
- Cryptographic core (AES-GCM, PBKDF2/Argon2id, RSA-OAEP).
- CLI (Typer), TUI (Textual), and GUI (Tauri) interfaces.
- SQLCipher-backed multi-user persistence.
- Audit log with hash-chained integrity.
- Comprehensive documentation: SPEC, ARCHITECTURE, THREAT_MODEL,
  CRYPTO_DECISIONS, CONVENTIONS, DEVELOPMENT.
- Architecture Decision Records (MADR v4) for all foundational choices.
- Spec-Driven Development workflow under `docs/specs/`.
- GitHub Actions CI (lint, type-check, tests, security scans, build).
- Pre-commit hooks (ruff, ty, bandit, conventional-commits, detect-secrets).

### Security
- Defense-in-depth: AES-GCM authenticated encryption + SQLCipher at-rest +
  RSA-OAEP for sharing + Cryptographic Erase for deletion.

[Unreleased]: https://github.com/sachamarlov/crypto-sidecar/compare/v0.0.0...HEAD
