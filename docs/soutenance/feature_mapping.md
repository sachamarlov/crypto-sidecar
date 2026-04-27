# Mapping CDC features → preuves dans le code (J-02)

Chaque ligne associe une feature ou un NFR du cahier des charges à
sa preuve concrète dans le repo. Référence pour les slides, le
démo script, et le Q&A.

> Hash main au moment de la rédaction : commit `ae27ad9` post-PR #36.

## Features fonctionnelles (`docs/SPEC.md` §3)

| ID   | Feature                                    | Statut | Preuve principale                                                                            |
| ---- | ------------------------------------------ | ------ | -------------------------------------------------------------------------------------------- |
| F-1  | Chiffrer un fichier ou un message          | ✅     | `core/operations.py:162 encrypt_file` + `core/operations.py:264 encrypt_message`             |
| F-2  | Déchiffrer un `.crypt` file                | ✅     | `core/operations.py:331 decrypt_file` (anti-oracle ADR-0015)                                 |
| F-3  | Chiffrer un message typé                   | ✅     | `cli/commands/encrypt.py --message` + `core/operations.py encrypt_message`                   |
| F-4  | Déchiffrer un message sans écriture        | ✅     | `cli/commands/decrypt.py --stdout` + `core/operations.py decrypt_message`                    |
| F-5  | Refuser un mot de passe faible             | ✅     | `security/password.py:assert_strong` + zxcvbn ≥ 3 + length ≥ 12                              |
| F-6  | Refuser path traversal                     | ✅     | `fileio/safe_path.py:resolve_within` (anti-`..` + anti-symlink + reparse points Win)         |
| F-7  | Menu console interactif                    | ✅     | `cli/commands/menu.py` (encrypt / decrypt / inspect / secure-delete / quit)                  |
| F-8  | Multi-utilisateurs locaux                  | ✅     | Spec 000-multi-user (Phase C-1 + C-2). `persistence/models.py User` + `cli/commands/user.py` |
| F-9  | Audit log hash-chained                     | ✅     | `security/audit.py:append/verify` + `cli/commands/history.py`                                |
| F-10 | GUI desktop moderne (Tauri)                | ✅     | Phase G sidecar (commit `a6c77eb`) + Phase H frontend (commit `ae27ad9`)                     |
| F-11 | Partage RSA-OAEP entre utilisateurs locaux | ✅     | `core/rsa.py` + `core/share_token.py` + `cli/commands/share.py + accept.py`                  |
| F-12 | Suppression sécurisée                      | ✅     | `core/secure_delete.py` (DoD 5220.22-M + crypto-erase metadata)                              |
| F-13 | Argon2id KDF opt-in                        | ✅     | `core/kdf.py:Argon2idKdf` + `cli/commands/encrypt.py --kdf argon2id`                         |
| F-14 | TUI Textual                                | ✅     | `ui/tui/app.py` + 6 screens (Phase F)                                                        |

## Non-functional requirements (`docs/SPEC.md` §4)

| ID    | Cible                                        | Statut | Mesure                                                                                      |
| ----- | -------------------------------------------- | ------ | ------------------------------------------------------------------------------------------- |
| NFR-1 | encrypt+decrypt ≥ 100 MiB/s                  | ✅     | `tests/perf/test_bench.py::test_aes_gcm_streaming_throughput` (CI floor 50 MiB/s, lab 100+) |
| NFR-2 | KDF dérivation 50ms ≤ T ≤ 1 s                | ✅     | `tests/perf/test_bench.py::test_pbkdf2_timing_within_nfr_2_band`                            |
| NFR-3 | CLI < 200 ms cold start, GUI < 1.5 s         | ⚠     | À mesurer Phase I (release binary)                                                          |
| NFR-4 | Sidecar < 100 MiB at idle                    | ⚠     | À mesurer Phase I                                                                           |
| NFR-5 | Distribuable Windows ≤ 80 MiB                | ⚠     | À mesurer Phase I (PyInstaller --strip + Tauri compress)                                    |
| NFR-6 | i18n FR + EN                                 | ✅     | `frontend/src/i18n/{fr,en}.json` (100+ clés) + `react-i18next`                              |
| NFR-7 | WCAG 2.2 AA                                  | ⚠     | Polish appliqué (focus rings + ARIA + reduced-motion). Audit axe-playwright deferred.       |
| NFR-8 | Coverage ≥ 80 % global, ≥ 95 % core/security | ✅     | `scripts/check_coverage_gates.py` (CI step bloquant)                                        |
| NFR-9 | CI green sur chaque merge                    | ✅     | `.github/workflows/ci.yml` (3 critical jobs Python/Frontend)                                |

## Architecture Decision Records

| ID       | Décision                                             | Statut             |
| -------- | ---------------------------------------------------- | ------------------ |
| ADR-0000 | MADR v4 pour les ADRs                                | accepted           |
| ADR-0001 | Tauri 2 + Python sidecar                             | accepted           |
| ADR-0002 | AES-GCM + dual KDF (PBKDF2 + Argon2id)               | accepted           |
| ADR-0003 | SQLCipher (Linux baseline)                           | superseded by 0011 |
| ADR-0004 | RSA-OAEP-SHA256 hybrid sharing (4096 bits)           | accepted           |
| ADR-0005 | Vite over Next.js                                    | accepted           |
| ADR-0006 | uv over Poetry                                       | accepted           |
| ADR-0007 | Conventional Commits + release-please                | accepted           |
| ADR-0008 | Spec-Driven Development                              | accepted           |
| ADR-0009 | GitHub fine-grained PAT                              | accepted           |
| ADR-0010 | Apache 2.0 license                                   | accepted           |
| ADR-0011 | Cross-platform DB encryption (column-level fallback) | accepted           |
| ADR-0012 | PyInstaller MVP, Nuitka post-CDC                     | accepted           |
| ADR-0013 | `.crypt` v1 container format                         | accepted           |
| ADR-0014 | Chunk-bound AAD for streaming AEAD                   | accepted           |
| ADR-0015 | Anti-oracle stderr unification                       | accepted           |
| ADR-0016 | Tauri sidecar IPC security                           | accepted           |

## Tests

| Type         | Fichiers                             | Compte          |
| ------------ | ------------------------------------ | --------------- |
| Unit         | `tests/unit/test_*.py`               | ~50 fichiers    |
| Integration  | `tests/integration/test_*.py`        | ~10 fichiers    |
| Property     | `tests/property/test_*_roundtrip.py` | 4 fichiers      |
| Perf         | `tests/perf/test_bench.py`           | 3 tests perf    |
| Frontend     | `frontend/src/**/*.test.ts(x)`       | 16 tests Vitest |
| Total Python |                                      | **607+ tests**  |

## Conformité grille évaluation GCS2 (estimé)

La grille officielle est dans le PDF du CDC. Items principaux :

1. Architecture du projet : 3/3 (hexagonal, séparation core/ui/persistence)
2. Crypto AES-GCM + PBKDF2 conforme : 3/3 (cf. ADR-0002, NIST SP 800-38D, OWASP 2026)
3. Anti-traversal : 3/3 (`fileio/safe_path.py`)
4. Validation password : 3/3 (zxcvbn ≥ 3 + length ≥ 12)
5. Menu console : 3/3 (`cli/commands/menu.py`)
6. Tests pytest : 3/3 (607+)
7. Format conteneur `.crypt` : 3/3 (versionné, magic, chunk-bound AAD)
8. Multi-user (extension) : 3/3 (Phase C)
9. Audit log (extension) : 3/3 (hash-chained + verify)
10. GUI moderne (extension) : 3/3 (Tauri + React + shadcn)
11. RSA share (extension) : 3/3 (RSA-OAEP + RSA-PSS + .gbox-share v1)
12. Secure delete (extension) : 3/3 (DoD + SSD detect)
13. Argon2id (extension) : 3/3
14. TUI (extension) : 3/3
15. Documentation : 3/3 (SPEC + ARCHITECTURE + THREAT_MODEL + CRYPTO_DECISIONS + 17 ADRs)
16. Threat model STRIDE : 3/3
17. CI/CD : 3/3
18. Conventional Commits + release-please : 3/3
19. Anti-oracle (sortie hors scope) : 3/3 (ADR-0015)
20. Tauri sidecar IPC (sortie hors scope) : 3/3 (ADR-0016)

Visée : 20×3 = 60 → note finale 20×60/60 = **20/20**.
