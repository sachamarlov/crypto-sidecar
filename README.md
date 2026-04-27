# GuardiaBox

> Coffre-fort numérique sécurisé local — chiffrement, partage et stockage sans
> compromis, conçu pour ne jamais faire confiance à un serveur distant.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![Tauri 2](https://img.shields.io/badge/Tauri-2.x-orange.svg)](https://tauri.app/)
[![Code style: ruff](https://img.shields.io/badge/code_style-ruff-000000.svg)](https://github.com/astral-sh/ruff)

**Statut** : 🚧 En développement actif (avril 2026 — projet académique GCS2 / DevSecOps).

---

## Présentation

**GuardiaBox** est une application de bureau permettant de chiffrer, déchiffrer,
stocker et partager des fichiers ou des messages de manière sécurisée. Tout
fonctionne **localement** sur votre machine : aucune donnée ne quitte le poste,
aucune dépendance à un service cloud, aucun compte distant à créer.

L'architecture repose sur les bonnes pratiques cryptographiques modernes 2026 :

- **AES-GCM** pour le chiffrement authentifié (NIST SP 800-38D).
- **PBKDF2-HMAC-SHA256** (≥ 600 000 itérations, OWASP FIPS-140) ou
  **Argon2id** (m=64 MiB, t=3, p=1) pour la dérivation de clé.
- **RSA-OAEP** dans un cryptosystème hybride pour le partage entre utilisateurs.
- **SQLCipher** pour le chiffrement de la base SQLite locale au repos.
- **Cryptographic erase** + overwrite multi-passes pour la suppression sécurisée
  (NIST SP 800-88r2).

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                guardiabox.exe (≈ 15 MB, Windows)                │
│                                                                 │
│  ┌──────────────────────┐      ┌────────────────────────────┐   │
│  │  Tauri 2 shell (Rust)│      │  Frontend bundle (Vite/    │   │
│  │  • WebView2 native   │◄────►│  React 19/shadcn/Framer)   │   │
│  │  • Frameless window  │ IPC  │  • UI moderne 60fps        │   │
│  │  • Tray + shortcuts  │      │  • Glassmorphism + WebGL   │   │
│  └──────────┬───────────┘      └────────────────────────────┘   │
│             │                                                   │
│             │ spawn + HTTP loopback (127.0.0.1:random_port)     │
│             ▼                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Python sidecar (FastAPI, bundled by PyInstaller)        │   │
│  │  • cryptography, argon2-cffi, zxcvbn-python              │   │
│  │  • SQLAlchemy 2.0 + SQLCipher                            │   │
│  │  • Hexagonal architecture: core ← adapters               │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

Trois interfaces utilisateur partagent le même cœur Python :

- **CLI** (Typer) — pour les scripts et l'automation.
- **TUI** (Textual) — pour une expérience console riche.
- **GUI moderne** (Tauri + React + shadcn) — pour la démo grand écran.

## Fonctionnalités

### Version livrée sur `main` (au 2026-04-27)

- ✅ Chiffrer / déchiffrer un fichier ou un message (AES-GCM + PBKDF2 /
  Argon2id), specs 001 + 002.
- ✅ Format conteneur `.crypt` v1 versionné, magic header, AAD chunk-bound
  anti-truncation (ADR-0013 + ADR-0014).
- ✅ Anti-oracle vérifié byte à byte via subprocess
  (ADR-0015, [tests/unit/test_cli_anti_oracle.py](tests/unit/test_cli_anti_oracle.py)).
- ✅ Suppression sécurisée par écrasement DoD 5220.22-M multi-pass
  - détection SSD cross-platform (spec 004 Phase B1).
- ✅ Validation entrées (zxcvbn length ≥ 12 / score ≥ 3, anti path-traversal,
  reparse points Windows rejetés).
- ✅ Inspection d'un conteneur `.crypt` sans déchiffrement (`guardiabox inspect`).
- ✅ Menu console interactif `guardiabox menu` (CDC F-7 — trois actions CDC +
  inspection + suppression sécurisée).
- ✅ **Multi-utilisateurs locaux** (spec 000-multi-user) — base SQLite avec
  chiffrement colonne par colonne (AES-GCM + HMAC index, ADR-0011) et
  triggers `audit_log` append-only.
- ✅ Keystore par utilisateur (RSA-4096 + clé de coffre AES-256) avec
  `create` / `unlock` / `change_password` (re-wrap sans re-chiffrer
  les `.crypt`).
- ✅ Journal d'audit hash-chained (`security.audit.append/verify`),
  vérification d'intégrité via `guardiabox doctor --verify-audit`.
- ✅ CLI multi-utilisateur : `guardiabox init`, `guardiabox user
{create,list,show,delete}`, `guardiabox history --filter --format`,
  `guardiabox doctor`.
- ✅ Flag opt-in `--vault-user <name>` sur `encrypt` / `decrypt` qui
  enregistre `file.encrypt` / `file.decrypt` dans le journal d'audit
  et persiste un `vault_items` row (T-000mu.13).
- ✅ **Partage RSA hybride entre utilisateurs locaux** (spec 003) —
  `guardiabox share` produit un jeton `.gbox-share` v1 (RSA-OAEP-SHA256
  pour le wrap de la DEK, RSA-PSS-SHA256 pour la signature détachée) ;
  `guardiabox accept` vérifie la signature **avant** tout déchiffrement
  (anti-oracle ADR-0015), unwrap la DEK avec la clé privée du
  destinataire, et restitue le clair. Empreinte SHA-256 de la clé
  publique destinataire affichée à l'envoi (mitigation AD-2).

- ✅ **Crypto-erase metadata + ciphertext overwrite** (spec 004 Phase B2) —
  `secure-delete --method crypto-erase --vault-user <nom>` combine
  l'écrasement DoD du `.crypt` avec la suppression de la ligne
  `vault_items` du coffre et l'inscription d'un `file.secure_delete`
  dans le journal d'audit. Limitation honnête : pas de DEK persistée
  par fichier dans l'archi actuelle, donc l'effacement strict NIST
  SP 800-88 reste roadmapé post-MVP via un format `.crypt` v2.
- ✅ Diagnostic `doctor --report-ssd` (probe SSD / HDD / inconnu).

### Roadmap — à implémenter avant la soutenance

- 🔨 TUI Textual — spec 000-tui.
- 🔨 GUI Tauri + React — spec 000-tauri-sidecar + frontend.

### Roadmap post-MVP

- 🔄 Authentification matérielle (YubiKey, Windows Hello).
- 🔄 2FA TOTP / WebAuthn.
- 🔄 Anti brute-force (backoff exponentiel + lockout).
- 🔄 Sync entre instances locales via fichier `.gbox-share` exportable.

## Stack technique

| Couche            | Technologies                                                               |
| ----------------- | -------------------------------------------------------------------------- |
| Frontend GUI      | Tauri 2, React 19, TypeScript, Vite, Tailwind v4, shadcn/ui, Framer Motion |
| Sidecar backend   | Python 3.12+, FastAPI, Pydantic v2, uvicorn, SQLAlchemy 2 async            |
| Cryptographie     | `cryptography` (pyca), `argon2-cffi`, SQLCipher                            |
| Persistence       | SQLite (chiffrée via SQLCipher), Alembic migrations                        |
| CLI               | Typer + Rich                                                               |
| TUI               | Textual                                                                    |
| Tests             | pytest, hypothesis (property-based), pytest-cov, pytest-asyncio            |
| Qualité           | ruff (lint+format), ty (types), bandit (sécurité), pre-commit              |
| Build & packaging | uv (Python deps), pnpm (Node deps), PyInstaller (sidecar), Tauri build     |
| CI/CD             | GitHub Actions (lint, tests, security scan, build, release)                |

## Démarrage rapide

### Prérequis

- Python ≥ 3.12
- Node.js ≥ 22 + pnpm ≥ 10
- Rust toolchain (pour Tauri) : `rustup`
- uv : `pip install uv` ou `curl -LsSf https://astral.sh/uv/install.sh | sh`

### Installation

```bash
git clone https://github.com/sachamarlov/crypto-sidecar.git
cd crypto-sidecar
uv sync
pnpm --dir src/guardiabox/ui/tauri/frontend install
```

### Lancement en mode développement

```bash
# CLI — voir toutes les commandes
uv run guardiabox --help

# Chiffrer / déchiffrer un fichier (AES-GCM + PBKDF2 par défaut)
uv run guardiabox encrypt rapport.pdf
uv run guardiabox decrypt rapport.pdf.crypt

# Chiffrer avec Argon2id à la place (m=64 MiB, t=3, p=1)
uv run guardiabox encrypt rapport.pdf --kdf argon2id

# Chiffrer un message court (stockage ou tuyau shell)
uv run guardiabox encrypt --message "secret à transmettre" -o note.crypt
uv run guardiabox decrypt note.crypt --stdout

# Inspecter l'en-tête d'un conteneur sans le déchiffrer
uv run guardiabox inspect rapport.pdf.crypt

# Supprimer de manière sécurisée (DoD 3-pass ; prévient sur SSD)
uv run guardiabox secure-delete rapport.pdf --passes 3

# Crypto-erase = overwrite + suppression ligne vault DB + audit
uv run guardiabox secure-delete rapport.pdf.crypt \
    --method crypto-erase --vault-user alice

# Initialiser le coffre multi-utilisateur (~/.guardiabox/vault.db)
uv run guardiabox init

# Gérer les utilisateurs locaux
uv run guardiabox user create alice
uv run guardiabox user list
uv run guardiabox user show alice

# Consulter le journal d'audit + vérifier la chaîne d'intégrité
uv run guardiabox history --limit 50 --format table
uv run guardiabox doctor --verify-audit

# Encrypt avec audit (--vault-user opt-in)
uv run guardiabox encrypt rapport.pdf --vault-user alice

# Partage RSA hybride entre deux utilisateurs locaux
# (Alice partage rapport.pdf.crypt → Bob l'accepte)
uv run guardiabox share rapport.pdf.crypt --from alice --to bob \
    -o rapport.gbox-share --expires 7
uv run guardiabox accept rapport.gbox-share --from alice --as bob \
    -o rapport-recu.pdf

# TUI
uv run guardiabox-tui

# GUI Tauri (dev mode avec HMR)
pnpm --dir src/guardiabox/ui/tauri/frontend tauri dev
```

### Codes de sortie (POSIX)

| Code | Signification                                                    |
| ---- | ---------------------------------------------------------------- |
| 0    | Succès                                                           |
| 1    | Erreur générique                                                 |
| 2    | Mot de passe incorrect ou conteneur altéré (anti-oracle)         |
| 3    | Chemin refusé ou fichier introuvable                             |
| 64   | Usage invalide (EX_USAGE)                                        |
| 65   | Erreur de données — conteneur malformé, KDF inconnu (EX_DATAERR) |
| 130  | Interrompu par l'utilisateur (SIGINT)                            |

### Tests

```bash
uv run pytest
uv run pytest --cov=guardiabox --cov-report=html
```

### Build production

```bash
# Sidecar Python (PyInstaller bundle)
uv run python scripts/build_sidecar.py

# GUI complète (.exe Windows)
pnpm --dir src/guardiabox/ui/tauri/frontend tauri build
```

## Documentation

| Document                                             | Contenu                                                                    |
| ---------------------------------------------------- | -------------------------------------------------------------------------- |
| [docs/SPEC.md](docs/SPEC.md)                         | Vision produit et critères d'acceptation                                   |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)         | Architecture technique détaillée                                           |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)         | Modèle de menace STRIDE et mitigations                                     |
| [docs/CRYPTO_DECISIONS.md](docs/CRYPTO_DECISIONS.md) | Justifications cryptographiques (NIST/OWASP/RFC)                           |
| [docs/CONVENTIONS.md](docs/CONVENTIONS.md)           | Règles de code (SOLID, DRY, naming, layering)                              |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)           | Guide développeur (setup, debug, troubleshooting)                          |
| [docs/adr/](docs/adr/)                               | Architecture Decision Records (MADR v4) — 16 entrées (ADR-0000 à ADR-0015) |
| [docs/specs/](docs/specs/)                           | Spec-Driven Development par fonctionnalité                                 |
| [docs/cahier-des-charges/](docs/cahier-des-charges/) | Cahier des charges officiel GCS2                                           |

### Architecture Decision Records actuels

| ID   | Titre                                                      | Statut             |
| ---- | ---------------------------------------------------------- | ------------------ |
| 0000 | Record architectural decisions using MADR                  | accepted           |
| 0001 | Use Tauri 2 with a Python sidecar for the desktop GUI      | accepted           |
| 0002 | AES-GCM with dual KDF (PBKDF2 default, Argon2id opt-in)    | accepted           |
| 0003 | Encrypt the SQLite database at rest with SQLCipher         | superseded by 0011 |
| 0004 | RSA-OAEP-SHA256 hybrid cryptosystem for sharing            | accepted           |
| 0005 | Vite over Next.js for the Tauri frontend                   | accepted           |
| 0006 | `uv` over Poetry / pip for Python dependency management    | accepted           |
| 0007 | Conventional Commits enforced by `release-please`          | accepted           |
| 0008 | Spec-Driven Development workflow                           | accepted           |
| 0009 | GitHub fine-grained PAT for the autonomy agent             | accepted           |
| 0010 | Apache License 2.0 for the project                         | accepted           |
| 0011 | Cross-platform database encryption strategy                | accepted           |
| 0012 | PyInstaller for MVP, planned migration to Nuitka post-CDC  | accepted           |
| 0013 | `.crypt` container v1 on-disk format                       | accepted           |
| 0014 | Chunk-bound AAD for streaming AEAD                         | accepted           |
| 0015 | Anti-oracle: unify stderr and exit code on decrypt failure | accepted           |

## Sécurité

GuardiaBox est conçu avec un **modèle zéro-confiance** : aucune donnée en clair
ne doit jamais quitter la mémoire protégée du processus, et aucun secret n'est
stocké en clair sur disque.

Pour signaler une vulnérabilité, lire [SECURITY.md](SECURITY.md).

Le modèle de menace complet est documenté dans [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Contribuer

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les règles de contribution
(branching, conventional commits, code review).

## Licence

Distribué sous licence Apache 2.0 — voir [LICENSE](LICENSE).

## Crédits

Projet académique réalisé dans le cadre de l'UE 7 « DevSecOps » du Bachelor 2 de
[Gaming Campus](https://gamingcampus.fr/), promotion 2025-2026.

Architecture, code et documentation : Sacha Marlov, avec l'assistance de
**Claude Code (Opus 4.7, contexte 1M)** d'Anthropic en mode autonomie.

Encadrant : Sylvain Labasse — [syllab.com](https://syllab.com).
