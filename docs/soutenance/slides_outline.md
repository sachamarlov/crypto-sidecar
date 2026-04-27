# Slides soutenance 29/04/2026 — outline (J-03)

> Brouillon prêt à coller dans Google Slides. Format 16:9, charte
> sombre, police Inter. 12 slides, 10 min de présentation.

---

## Slide 1 — Couverture

```
GuardiaBox
Coffre-fort numérique sécurisé local

Sacha Marlov · GCS2 · UE 7 DevSecOps · 29/04/2026
Encadrant : Sylvain Labasse

github.com/sachamarlov/crypto-sidecar
```

---

## Slide 2 — Pourquoi un coffre 100 % local ?

- Modèle **zéro-confiance** : aucune donnée ne quitte le poste.
- Pas de cloud, pas de compte distant, pas de service tiers.
- Pour : pentesters, journalistes, citoyens cybersécurité-conscients.
- Différenciation : Bitwarden / 1Password sont cloud-first ; nos
  données sont chiffrées sur leurs serveurs mais on doit faire
  confiance à leur infrastructure et à leur posture.

---

## Slide 3 — Architecture

```
┌─────────────────────────────────────────────┐
│         guardiabox.exe (Tauri shell)         │
│  ┌─────────────┐    ┌────────────────────┐   │
│  │ Tauri Rust  │◄──►│ React 19 + shadcn  │   │
│  │ (WebView2)  │    │ Vite + Tailwind v4 │   │
│  └─────┬───────┘    └────────────────────┘   │
│        │ spawn + 127.0.0.1:<random_port>     │
│        ▼                                     │
│  ┌──────────────────────────────────────┐    │
│  │ Python sidecar (FastAPI bundled)     │    │
│  │ cryptography + argon2 + sqlalchemy   │    │
│  └──────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```

Hexagonal : `core` (pur, no I/O) ← adapters CLI / TUI / Tauri.
3 process : Tauri shell + WebView2 renderer + Python sidecar.

---

## Slide 4 — Stack technique

| Couche          | Technologies                                               |
| --------------- | ---------------------------------------------------------- |
| **GUI**         | Tauri 2 + React 19 + Vite 6 + Tailwind v4 + shadcn/ui      |
| **Sidecar**     | FastAPI + Pydantic v2 + uvicorn + slowapi                  |
| **Crypto**      | `cryptography` (pyca) + `argon2-cffi` + zxcvbn             |
| **Persistence** | SQLAlchemy 2 async + aiosqlite + Alembic                   |
| **CLI / TUI**   | Typer + Rich / Textual                                     |
| **Build**       | uv (Python) + pnpm (Node) + PyInstaller + Tauri            |
| **Quality**     | ruff + mypy strict + bandit + pytest + Hypothesis + Vitest |

---

## Slide 5 — Cryptographie

```
PBKDF2-HMAC-SHA256, 600 000 iter (OWASP 2026)
                 │
                 ▼
            32-byte AES-256 key
                 │
                 ▼
   AES-256-GCM (NIST SP 800-38D)
   nonce 12B per chunk · tag 128 bits
```

**Format `.crypt` v1** :
`magic GBOX | version | kdf_id | params | salt 16B | nonce 12B | chunks…`

**AAD chunk-bound** : `header || (chunk_idx, is_final)` (ADR-0014)
→ truncation, reordering, header swap = tag invalide.

**Argon2id 64 MiB / 3 / 1** opt-in (RFC 9106 / OWASP 2026).
**RSA-OAEP-SHA256 4096 bits** pour wrap DEK + **RSA-PSS-SHA256**
pour signer `.gbox-share` v1 (ADR-0004).

---

## Slide 6 — Anti-oracle (la décision la plus subtile)

> Un attaquant qui peut différencier "wrong password" de
> "tampered ciphertext" peut reconstruire la clé en O(n²) requêtes
> (cf. Bleichenbacher 1998, padding oracles CBC).

**Notre invariant** :

- Wrong password → `stderr = "Échec…", exit 2`
- Tampered tag → `stderr = "Échec…", exit 2` ← **byte-identique**

Comment :

- `core/operations.decrypt_file` : pas de `structlog.warning` sur
  failure (le simple fait d'émettre un événement est un canal
  observable).
- `IntegrityError` ∪ `DecryptionError` ∪ `CorruptedContainer`
  (sur truncation post-KDF) → `ANTI_ORACLE_MESSAGE` unifié.
- Test : `subprocess.run` (CliRunner aveugle aux logs autres).
- Propagé jusqu'à HTTP 422 + JSON body constant (Tauri).
- Propagé au toast i18n du frontend.

**ADR-0015 + ADR-0016 sec C**.

---

## Slide 7 — Threat Model STRIDE

| Boundary              | Adversaire    | Mitigation                                         |
| --------------------- | ------------- | -------------------------------------------------- |
| Network → app         | AD-1 (remote) | Aucune surface : sidecar bind 127.0.0.1 only       |
| Local procs → sidecar | AD-2          | Per-launch token 32 octets + `hmac.compare_digest` |
| Local user → DB       | AD-3          | Column-level AES-GCM (ADR-0011) + OS BitLocker     |
| Curieux dev           | AD-4          | Open source ; rien à cacher                        |
| Recipient malveillant | AD-5          | RSA-PSS signature + content_sha256                 |
| Cold-boot / DMA       | AD-6          | **Out of scope** (mitigation OS-level)             |

`docs/THREAT_MODEL.md` détaille STRIDE par boundary, 6 adversaires,
4 risques résiduels acknowledged.

---

## Slide 8 — Multi-utilisateurs + audit log

```
User
 ├─ Keystore (RSA-4096 + Vault key 256 bits)
 │    wrapped under master key (PBKDF2(password))
 ├─ encrypt → vault_items row (filename HMAC indexed)
 └─ audit_log entry (hash-chained)

         entry_hash[N] = SHA-256(prev_hash || canonical_json(N))
```

- 4 tables : `users`, `vault_items`, `shares`, `audit_log`.
- Trigger SQL append-only sur `audit_log` (refus UPDATE/DELETE).
- `guardiabox doctor --verify-audit` walks chain genesis → last.
- Tampering détecté byte-by-byte (test forensique).

---

## Slide 9 — Démo (live)

1. **Init** vault (`/api/v1/init`).
2. **Unlock** + admin password.
3. **Create users** alice + bob.
4. **Encrypt** `rapport.pdf` as alice (Argon2id).
5. **Share** alice → bob avec **fingerprint confirm**.
6. Switch active user → bob, **Accept** → recover plaintext.
7. **Verify chain** → ok=true.
8. **Anti-oracle** : montrer wrong-pwd vs tampered tag (CLI,
   stderr identique).

(Si problème : screenshots dans `docs/soutenance/screenshots/`.)

---

## Slide 10 — Qualité + CI

**Tests** :

- 607+ Python (unit + integration + property + perf)
- 16 Vitest
- Coverage ≥ 95 % core / security (CI gate bloquant)

**CI** (3 jobs critiques verts) :

- Python ubuntu-latest + windows-latest
- Frontend Node 22

**Quality gates locaux + CI** :

- `ruff` strict + format
- `mypy --strict`
- `bandit -r src/`
- `pip-audit`
- `pnpm audit`
- `detect-secrets`
- `pre-commit` (commit-msg conventional)

37 PRs mergées sur `main`. 17 ADRs (MADR v4).

---

## Slide 11 — Conformité CDC

| ID           | Feature                                                  | Statut                  |
| ------------ | -------------------------------------------------------- | ----------------------- |
| F-1..F-7     | MVP CDC obligatoire (encrypt, decrypt, validation, menu) | ✅                      |
| F-8          | Multi-user                                               | ✅                      |
| F-9          | Audit log                                                | ✅                      |
| F-10         | GUI Tauri + React                                        | ✅                      |
| F-11         | RSA share                                                | ✅                      |
| F-12         | Secure delete                                            | ✅                      |
| F-13         | Argon2id opt-in                                          | ✅                      |
| F-14         | TUI Textual                                              | ✅                      |
| NFR-1..NFR-2 | Perf encrypt + KDF                                       | ✅ tests CI             |
| NFR-6        | i18n FR + EN                                             | ✅                      |
| NFR-7        | WCAG 2.2 AA polish                                       | ✅ (axe audit deferred) |
| NFR-8..NFR-9 | Coverage + CI gates                                      | ✅                      |

**Visée 20/20 grille évaluation**.

---

## Slide 12 — Conclusion + roadmap post-CDC

**Livré** : 14 features + 9 NFR + 17 ADRs + 7 specs.

**Post-MVP (tracé)** :

- Migration PyInstaller → **Nuitka** (ADR-0012) : binary natif,
  cold start <500ms, plus de false positive AV.
- **EV code-signing cert** (ADR-0018) post-soutenance.
- **Hardware tokens** : YubiKey (PIV) + Windows Hello / TPM.
- **Sync LAN** entre instances locales (toujours zéro-cloud).
- **WebSocket /api/v1/stream** pour progress events sur les
  longues opérations (G-10 deferred).
- **`.crypt` v2** avec DEK persistée → vrai NIST SP 800-88
  crypto-erase.

> **Merci.** Questions ?

---

## Notes export Google Slides

- Police : Inter (Bold pour titres, Regular pour corps).
- Couleurs : background `#0F1419`, text `#E8EAED`, accent
  `oklch(0.7 0.18 260)` (= `#7C5CFF` approx).
- Ne pas dépasser 7 lignes par slide. Si oui, splitter ou alléger.
- Mettre les screenshots de démo en backup (slide 13-15 cachées).
