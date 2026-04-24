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

### Version livrée (CDC)

- ✅ Chiffrer / déchiffrer un fichier ou un message (AES-GCM + PBKDF2/Argon2id)
- ✅ Format conteneur `.crypt` versionné, magic header, intégrité GCM
- ✅ Multi-utilisateurs locaux (SQLCipher)
- ✅ Historique des opérations (audit log hash-chained)
- ✅ Partage entre utilisateurs locaux (RSA-OAEP cryptosystème hybride)
- ✅ Suppression sécurisée (overwrite multi-passes + cryptographic erase)
- ✅ Validation entrées (zxcvbn, anti path-traversal)
- ✅ Anti brute-force (backoff exponentiel + lockout)

### Roadmap post-livraison

- 🔄 Authentification matérielle (YubiKey, Windows Hello)
- 🔄 2FA TOTP / WebAuthn
- 🔄 Sync entre instances locales via fichier `.gbox-share` exportable

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

| Document                                             | Contenu                                              |
| ---------------------------------------------------- | ---------------------------------------------------- |
| [docs/SPEC.md](docs/SPEC.md)                         | Vision produit et critères d'acceptation             |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)         | Architecture technique détaillée                     |
| [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)         | Modèle de menace STRIDE et mitigations               |
| [docs/CRYPTO_DECISIONS.md](docs/CRYPTO_DECISIONS.md) | Justifications cryptographiques (NIST/OWASP/RFC)     |
| [docs/CONVENTIONS.md](docs/CONVENTIONS.md)           | Règles de code (SOLID, DRY, naming, layering)        |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)           | Guide développeur (setup, debug, troubleshooting)    |
| [docs/adr/](docs/adr/)                               | Architecture Decision Records (MADR v4) — 13 entrées |
| [docs/specs/](docs/specs/)                           | Spec-Driven Development par fonctionnalité           |
| [docs/cahier-des-charges/](docs/cahier-des-charges/) | Cahier des charges officiel GCS2                     |

### Architecture Decision Records actuels

| ID   | Titre                                                     | Statut             |
| ---- | --------------------------------------------------------- | ------------------ |
| 0000 | Record architectural decisions using MADR                 | accepted           |
| 0001 | Use Tauri 2 with a Python sidecar for the desktop GUI     | accepted           |
| 0002 | AES-GCM with dual KDF (PBKDF2 default, Argon2id opt-in)   | accepted           |
| 0003 | Encrypt the SQLite database at rest with SQLCipher        | superseded by 0011 |
| 0004 | RSA-OAEP-SHA256 hybrid cryptosystem for sharing           | accepted           |
| 0005 | Vite over Next.js for the Tauri frontend                  | accepted           |
| 0006 | `uv` over Poetry / pip for Python dependency management   | accepted           |
| 0007 | Conventional Commits enforced by `release-please`         | accepted           |
| 0008 | Spec-Driven Development workflow                          | accepted           |
| 0009 | GitHub fine-grained PAT for the autonomy agent            | accepted           |
| 0010 | Apache License 2.0 for the project                        | accepted           |
| 0011 | Cross-platform database encryption strategy               | accepted           |
| 0012 | PyInstaller for MVP, planned migration to Nuitka post-CDC | accepted           |

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
