# Démo script soutenance 29/04/2026 (J-04)

> Présentation orale 10 minutes + Q&A. Chronométrage ci-dessous.
> Backup : screenshots dans `docs/soutenance/screenshots/` au cas
> où la démo plante.

## Préparation matérielle (avant démo)

- Laptop chargé + alimentation + adaptateur HDMI/USB-C.
- VS Code ouvert sur le repo (montrer arbo si demandé).
- Terminal 1 : `uv run guardiabox-sidecar` (sidecar live, port + token visibles).
- Terminal 2 : `uv run guardiabox` (CLI prête à l'emploi).
- Terminal 3 : `pnpm --dir src/guardiabox/ui/tauri/frontend tauri dev` (GUI avec HMR).
- Internet (Github + slides Google) en backup.
- Données démo : un `~/Demo/rapport.pdf` factice (1 MiB).

## Timeline (10 min)

### 00:00 - 00:30 — Couverture (slide 1)

> "Bonjour, je présente GuardiaBox, un coffre-fort numérique
> sécurisé local développé pour le projet n°4 de l'UE 7 DevSecOps.
> Réalisé en autonomie en parallèle de mon stage NDA. Le code est
> sur sachamarlov/crypto-sidecar, 36 PRs mergées."

### 00:30 - 01:30 — Problème + vision (slide 2)

Cite Bitwarden / 1Password (cloud). Approche zéro-confiance,
100% local, multi-interface (CLI + TUI + GUI moderne).

### 01:30 - 02:30 — Architecture (slide 3-4)

Schema 3 process : Tauri shell + Python sidecar + WebView2.
Hexagonal : core pure → adapters CLI/TUI/Tauri. 17 ADRs.

### 02:30 - 03:30 — Cryptographie (slide 5)

- AES-256-GCM (NIST SP 800-38D)
- PBKDF2-HMAC-SHA256 600 000 itérations (OWASP 2026 FIPS-140)
- Argon2id 64 MiB / 3 / 1 (OWASP 2026 par défaut, opt-in)
- RSA-OAEP-SHA256 4096 bits (PKCS#1 v2.2)
- HMAC-SHA-256 + `hmac.compare_digest`

Format `.crypt` v1 versionné, magic `GBOX`, chunk-bound AAD.

### 03:30 - 04:30 — Anti-oracle (slide 6) **DÉMO CLI**

```bash
# Terminal 2
$ guardiabox encrypt rapport.pdf
[prompt password] Correct_Horse_Battery_Staple_42!
$ guardiabox decrypt rapport.pdf.crypt
[prompt] Wrong_Password_42!
# stderr: "Échec du déchiffrement. Mot de passe incorrect ou conteneur altéré."
# exit 2

$ python -c "import pathlib; p=pathlib.Path('rapport.pdf.crypt'); raw=bytearray(p.read_bytes()); raw[-1]^=1; p.write_bytes(bytes(raw))"

$ guardiabox decrypt rapport.pdf.crypt
[prompt] Correct_Horse_Battery_Staple_42!
# stderr IDENTIQUE (byte-byte) + exit 2
```

> "Le message d'erreur est byte-pour-byte identique. ADR-0015
> documente comment on a éliminé tous les oracles : pas de
> structlog event différencié, exit code unifié, tests
> subprocess-level (CliRunner aveugle au leak). Le test
> `test_wrong_password_and_tampered_chunk_share_exact_stderr`
> verrouille l'invariant."

### 04:30 - 05:30 — Threat model (slide 7)

5 boundaries STRIDE. AD-1..AD-6 modélisés. Mitigations clés :
CSP, token launch 32 octets loopback, hash chain audit,
fingerprint pubkey display.

### 05:30 - 07:30 — **DÉMO GUI** (slide 8-9)

```
1. Init vault (terminal montrant les fichiers ~/.guardiabox/)
2. Unlock avec admin password
3. Création users alice + bob
4. Switch active user → alice
5. Encrypt rapport.pdf (file picker → KDF Argon2id → password)
6. Share rapport.pdf.crypt → bob
   - Étape 1 : fingerprint visible
   - Étape 2 : confirmation
7. Lock + switch → bob
8. Accept rapport.gbox-share → recover plaintext
9. Verify chain (history modal) → ok=true
10. Crypto-erase via CLI (rapide à montrer)
```

### 07:30 - 08:30 — Qualité + CI (slide 10)

- 607+ tests Python + 16 Vitest
- Coverage 95+ % core + security
- ruff strict + mypy strict + bandit + pip-audit + detect-secrets
- 3 jobs CI critiques verts

Montrer `gh pr list --state merged | head -10` ou screenshots.

### 08:30 - 09:30 — Conformité CDC (slide 11)

Tableau 14 features F-1..F-14 + 9 NFR + 17 ADRs.
Visée 20/20 grille.

### 09:30 - 10:00 — Conclusion + roadmap (slide 12)

Post-CDC :

- Nuitka migration (cf. ADR-0012)
- EV code-signing cert
- Hardware tokens (YubiKey, Windows Hello)
- Sync LAN entre instances locales (toujours zéro-cloud)

> "Merci. Questions ?"

## Plan B en cas de bug pendant la démo

| Symptôme                   | Fallback                                                       |
| -------------------------- | -------------------------------------------------------------- |
| Tauri shell ne démarre pas | Démo CLI uniquement (`guardiabox encrypt/decrypt`)             |
| Sidecar ne répond pas      | Démo CLI + screenshots GUI                                     |
| Reseau interne tombe       | Démo offline OK ; lien GitHub déjà cliqué dans onglet          |
| Démo prend trop de temps   | Skip secure-delete + accept (les flux clés sont encrypt+share) |

## Répétitions

| #   | Date        | Durée mesurée | Notes                 |
| --- | ----------- | ------------- | --------------------- |
| 1   | 28/04       | TBD           | Devant un public test |
| 2   | 28/04       | TBD           | Seul, chronométré     |
| 3   | 29/04 matin | TBD           | Dernière passe        |

Cible : 9:30 - 10:00. Si > 10:00, supprimer la démo crypto-erase.
