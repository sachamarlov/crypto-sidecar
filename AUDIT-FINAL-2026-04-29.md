# AUDIT FINAL GuardiaBox — Master Punch List

> Date : 2026-04-29 — Soutenance : J+1
> Synthèse de 5 audits parallèles (172 KiB) en master deduplicated punch list.
> Sources : `audit-backend.md`, `audit-frontend.md`, `audit-security.md`,
> `audit-devops.md`, `audit-quality-polish.md`.

## 0. Executive summary

État réel à T-24h de la soutenance, après dédup cross-team :

- **22 findings P0 uniques** (sur 31 bruts cumulés ; 9 trouvés par ≥ 2 équipes
  indépendantes — signal de maturité).
- **Crypto core solide** (AES-GCM streaming, AAD chunk-bound ADR-0014, anti-oracle
  ADR-0015 propagé jusqu'au HTTP byte-identique). 0 CVE crypto ouverte.
- **3 trous structurels critiques** :
  1. ADR-0016 §D rate-limit décrit mais **0 décorateur appliqué** — brute-force
     `/vault/unlock` illimité (vu par C-sécu P0-1, A-backend P1-3).
  2. Capabilities Tauri **bundles `*:default`** en violation directe CLAUDE.md
     §11 + devtools en release (vu par B-frontend P0-4, C-sécu P0-2,
     E-quality P0-9).
  3. NFC-normalisation **manquante sur `encrypt_message`** alors que
     `decrypt_message` la fait — silent data loss garanti pour utilisateurs
     macOS / clavier compose / IME (vu par A-backend P0-2, C-sécu P1-1).
- **Méta-finding DevOps capital** : 0/8 PRs de fix runtime aujourd'hui n'ont
  ajouté de test de régression. Les 8 bugs peuvent revenir demain, en pleine
  démo.
- **Recommandation 24h** : 5 fixes Tier A (~6-8 h), 3 fixes Tier B optionnels
  si temps (~4 h), reste post-soutenance. Détails ci-dessous.

## 1. Master Punch List P0 dédupliquée

Légende : **Sources** colonne = équipes ayant indépendamment trouvé le même
finding (A=backend, B=frontend, C=sécu, D=devops, E=quality). Les findings
multi-sources sont triés en haut comme signal de robustesse de l'analyse.

| #         | Catégorie      | Finding                                                                                                                                                                              | Sources                | Visible démo ?                   | Sévérité | Effort                  |
| --------- | -------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------- | -------------------------------- | -------- | ----------------------- |
| **P0-α**  | sécurité       | Rate-limiter slowapi déclaré mais **0 route décorée** — brute-force `/vault/unlock` illimité ; ADR-0016 §D promet 5/min, livré ~90/min                                               | C-P0-1, A-P1-3         | non (jury ne le testera pas)     | crit     | 30 min                  |
| **P0-β**  | sécurité       | Capabilities Tauri en bundles `*:default` (12 entrées) + `devtools` en release + CSP `style-src 'unsafe-inline'` ; CLAUDE.md §11 violation explicite                                 | B-P0-4, C-P0-2, E-P0-9 | oui (jury grep)                  | crit     | 1 h                     |
| **P0-γ**  | crypto         | `encrypt_message` ne NFC-normalise PAS le password ; `decrypt_message` le fait — silent data loss                                                                                    | A-P0-2, C-P1-1         | non (sauf utilisateur internat.) | crit     | 15 min                  |
| **P0-δ**  | sécurité       | `/api/v1/secure-delete` accepte path absolu sans `resolve_within` — DoD-erase n'importe quel fichier user-writable                                                                   | A-P0-1                 | non                              | crit     | 30 min                  |
| **P0-ε**  | sécurité       | Sidecar encrypt/decrypt passent `root=source.parent` à `resolve_within` — garde inopérante, plaintext output n'importe où                                                            | C-P1-2                 | non                              | crit     | 45 min                  |
| **P0-ζ**  | sécurité       | `vault.admin.json` non signé/HMAC — substitution offline DoS le vault                                                                                                                | C-P0-3                 | non (AD-2 offline)               | crit     | 1 h                     |
| **P0-η**  | sécurité       | `vault.lock` lit session_id du body au lieu d'`X-GuardiaBox-Session` — n'importe qui avec le launch token close une session arbitraire                                               | A-P0-3                 | non                              | high     | 20 min                  |
| **P0-θ**  | persistence    | `PRAGMA foreign_keys` jamais activé alors que schemas déclarent CASCADE/SET NULL — silent orphans après `delete user`                                                                | A-P0-4                 | non                              | high     | 1 h                     |
| **P0-ι**  | conformité ADR | ADR-0011 SQLCipher Linux mort dans le code (rejected par `database.py`) ; docs CRYPTO_DECISIONS / THREAT_MODEL / ARCHITECTURE annoncent encore SQLCipher                             | A-P0-5, C-P1-5         | possible (jury lit ADR)          | high     | 1 h (option B doc-only) |
| **P0-κ**  | UX bloquant    | Lock screen défaut → form **"Init vault"** pendant que `/readyz` charge (~5.7 s) ; returning user voit init CTA chaque cold start                                                    | B-P0-1                 | **oui** (chaque démarrage démo)  | high     | 1.5 h                   |
| **P0-λ**  | UX bloquant    | Frameless transparent window sans `data-tauri-drag-region` — fenêtre non déplaçable, pas de close/min/max                                                                            | B-P0-3                 | **oui** (multi-monitor)          | high     | 2 h                     |
| **P0-μ**  | UX bloquant    | Init vault password **sans champ confirmation** + sans ack "irrécupérable" — typo = lockout permanent du vault                                                                       | B-P0-6                 | **oui** (golden path)            | high     | 30 min                  |
| **P0-ν**  | UX bloquant    | Tous les `onError` collapsent en `errors.network` ("Failed to fetch") — pas de diagnostic visible si CORS/sidecar/AV                                                                 | B-P0-2                 | **oui** (déjà vécu aujourd'hui)  | high     | 2 h                     |
| **P0-ξ**  | code quality   | `App.tsx` dead bootstrap scaffold "v0.1.0" toujours bundlé — premier signal "starter template" pour un reviewer ouvrant l'IDE                                                        | E-P0-1                 | oui (review code)                | mid      | 30 s                    |
| **P0-ο**  | code quality   | `package.json` 70 deps, **6 importées** ; `argon2-browser` + `@noble/*` en deps UI = CLAUDE.md §11 violation (crypto en UI layer)                                                    | E-P0-2, B-P2-1, C-P1-3 | oui (review code)                | mid      | 30 min                  |
| **P0-π**  | UX             | Hard-coded `theme: "Dark"` + `defaultTheme="dark"` mais light tokens complets shippés dans `index.css` ; `next-themes` chargé pour rien, zéro toggle                                 | E-P0-3                 | oui (review UI)                  | mid      | 1 h                     |
| **P0-ρ**  | UX defensive   | Zéro `<ErrorBoundary>` malgré `react-error-boundary` en deps ; render exception = écran blanc, kill process                                                                          | E-P0-4, B-P1-1         | possible (regression)            | mid      | 1 h                     |
| **P0-σ**  | UX trust       | Auto-lock sans countdown UI ; `expiresAtMsAtom` jamais lu pour rendu — lock brutal sans warning                                                                                      | E-P0-5, B-P1-3         | oui (si démo > 5 min)            | mid      | 1 h                     |
| **P0-τ**  | UX             | `dragDropEnabled: true` activé dans `tauri.conf.json` mais aucun `onDragDropEvent` listener — drag PDF sur fenêtre = rien                                                            | E-P0-6                 | oui (test naturel jury)          | mid      | 45 min                  |
| **P0-υ**  | i18n           | `LABEL_BY_SCORE` password strength en français hardcodé ; switch EN garde "Très faible" — NFR-6 violation directe                                                                    | E-P0-7                 | oui (toggle FR/EN)               | low      | 15 min                  |
| **P0-φ**  | UX             | Empty states absents share/accept (dropdown affiche `--`) sans CTA "créer un destinataire" ; share fingerprint warning sans fingerprint affiché (mitigation ADR-0004 morte dans GUI) | E-P0-8, B-P1-8, B-P1-9 | oui (1er user seul)              | mid      | 1.5 h                   |
| **P0-χ**  | code quality   | `_settings`/`_store` dupliqué 4× alors que `dependencies.py` exporte la canonique — DRY rule of three breach acté                                                                    | E-P0-10                | non                              | low      | 20 min                  |
| **P0-ψ**  | DevOps         | **0/8 PRs runtime fix d'aujourd'hui n'ont ajouté de test de régression** ; les 8 bugs peuvent revenir                                                                                | D-P0-1                 | non                              | crit     | 2 h (4 tests)           |
| **P0-ω**  | DevOps         | Smoke-test bundled binary = `/healthz` only ; ne couvre pas argon2 ni Alembic (les 2 bugs d'aujourd'hui)                                                                             | D-P0-2                 | non                              | high     | 1 h                     |
| **P0-aa** | DevOps         | `Cargo.lock` gitignored ; build non-reproductible côté Rust (~600 deps transitives)                                                                                                  | D-P0-3                 | non                              | mid      | 5 min                   |
| **P0-bb** | DevOps         | Job CI `frontend` skip silencieux si `pnpm-lock.yaml` manquant — exactement comment bug #8 (TS strict Vite 7) a passé                                                                | D-P0-5                 | non                              | mid      | 5 min                   |
| **P0-cc** | DevOps         | Playwright e2e existe (1 spec, 8 lignes) mais jamais exécuté en CI — bug #1+#2 (CORS) invisibles à toute la pyramide de tests                                                        | D-P0-6                 | non                              | high     | 1 h                     |
| **P0-dd** | doc            | ADR-0016 §I "CORS Disabled" toujours fausse après PR #48 ; code amendé, ADR pas                                                                                                      | D-P0-4                 | possible (jury lit ADR)          | low      | 15 min                  |

(28 P0 finaux après dédup, vs 31 bruts cumulés. Les sub-items déjà couverts
par un finding parent — ex. "9 unused plugin permissions" couvert par
P0-β bundles `:default` — ne sont pas listés à part.)

## 2. Recommandation pour les 24h avant soutenance

Le standard prod-ready t'interdit de tout fixer en 24h. La logique :
**fix ce que le jury verra dans les 5 premières minutes**, **fix les
violations CLAUDE.md écrites noir sur blanc** (un reviewer va grep les
règles §11 et §9bis), **fix ce qui peut casser la démo**, **document le
reste**.

### Tier A — Bloquant 24h (5 items, ~7 h)

Si tu fais seulement ça, tu vas en soutenance avec un produit cohérent.

1. **P0-β** Capabilities granulaires + virer devtools release + CSP
   tighten — **CLAUDE.md §11 explicite, le jury va grep**. ~1 h.
2. **P0-α** Décorer `@limiter.limit(...)` sur `/vault/unlock` (priorité)
   - `/encrypt`, `/decrypt`, `/share`, `/accept` — **ADR-0016 §D explicite**.
     ~30 min + 1 test E2E. **Total ~1 h**.
3. **P0-γ** `_password_bytes(password)` à `operations.py:307` + 1 test
   property-based hypothesis NFC↔NFD round-trip. **15 min**.
4. **P0-κ + P0-ν** ensemble : BootSplash pendant `/readyz` + typed errors
   `SidecarUnreachableError {handshake|fetch|timeout}` au lieu du toast
   générique. ~3 h. C'est le **premier écran et la première erreur** du
   jury — investissement énorme par minute.
5. **P0-ψ** 4 tests de régression pour les 8 bugs d'aujourd'hui (CORS
   preflight, OPTIONS sans token, bundle imports argon2.low_level, bundle
   crée table users). 2 h.

**Total Tier A : ~7 h**, à répartir : tu peux faire 1+2+3 (~2.5 h
backend) en parallèle de 4 (~3 h frontend) si tu veux ; le 5 est en fin.

### Tier B — Si temps (3 items, ~4 h)

Items à haute valeur démo, mais que tu peux assumer "post-soutenance"
si Tier A déborde.

6. **P0-λ** Drag region + `<WindowControls />`. ~2 h. Bloquant si la
   machine de démo est multi-monitor ; non-bloquant si tu démarres
   centré et tu n'y touches plus.
7. **P0-μ** Confirm password + ack checkbox sur init flow. 30 min.
   Catastrophique si l'utilisateur fait une typo en démo ; survivable
   sinon.
8. **P0-ξ + P0-ο + P0-χ** trio cleanup : `rm App.tsx` + `pnpm remove`
   les ~50 deps mortes + dédup `_settings`/`_store`. Total ~1 h. Pure
   cosmétique, mais "package.json mince" est le signal #1 de
   professionalisme pour un reviewer code.

**Total Tier B : ~4 h**.

### Tier C — Workstream parallèle docs (1 h, peut faire le matin de la soutenance)

Si tu choisis de ne pas implémenter les fixes code, tu peux au minimum
**aligner les ADR et docs sur le shipping reality** pour préempter les
catches du jury :

9. **P0-ι option B** Update `docs/CRYPTO_DECISIONS.md`, `docs/THREAT_MODEL.md`,
   `docs/ARCHITECTURE.md`, ADR-0011 → "column-level AES-GCM uniformément,
   SQLCipher backlog post-MVP" + ADR-of-supersession. 1 h.
10. **P0-dd** Amend ADR-0016 §I CORS — 5 lignes markdown documentant la
    correction du PR #48. 15 min.

### Tier D — Post-soutenance (out of scope 24h)

Tous les autres P0 (δ, ε, ζ, η, θ, π, ρ, σ, τ, υ, φ, ω, aa, bb, cc) +
tous les P1 (~50) + tous les P2 (~45). Backlog clair pour Phase J ou
post-CDC.

`★ Mon avis personnel ────────────────────────────`
Je ferais Tier A + items 6 et 7 du Tier B = ~10 h sur 24, en gardant
6 h de marge pour répétitions Phase J (J-09) et imprévus. Le trio
cleanup (item 8) je le ferais le matin de la soutenance comme commit
"poli", pas avant — c'est cosmétique et tu n'as pas envie d'introduire
une régression à T-2h.
Tier C docs : à faire une fois le code stable, pas avant — sinon les
docs vont diverger du code à nouveau.
`─────────────────────────────────────────────────`

## 3. Trois questions à arbitrer

1. **Tu valides Tier A complet (~7 h) ou tu coupes ?** Si tu coupes,
   l'item le moins critique fonctionnellement est P0-α (rate-limit) car
   le jury ne va pas brute-forcer le sidecar — mais c'est aussi
   **l'écart ADR le plus visible** quand un reviewer lit ADR-0016 §D
   puis grep `@limiter.limit` et trouve 0.
2. **Tu veux Tier B intégral, ou seulement 6 (drag region) + 7 (init
   confirm) ?** Le trio cleanup (item 8) ajoute 1 h pour zéro impact
   fonctionnel — uniquement signal de soin.
3. **Sur P0-κ + P0-ν (Tier A item 4)**, ton standard "prod-ready par
   phase" implique de fixer les deux ensemble (ils touchent le même
   code path frontend). 3 h c'est le coût pour faire les deux
   proprement avec error boundaries (P0-ρ "rentre" gratis dans la
   refacto). Tu valides l'approche bundle, ou tu préfères P0-κ seul
   pour 1.5 h ?

## 4. Annexe — Backlog P1/P2 (post-soutenance)

Synthèse condensée pour la suite. Détails dans les `audit-{X}.md`
sources.

### Backend (P1) — A-P1

- P1-1 RSA private key DER non zero-fill (defense-in-depth)
- P1-2 `bootstrap.init_vault` admin_key non zero-fill
- P1-4 audit `target_hmac` deterministic (fingerprint stable, intentional)
- P1-5 `secure_delete` ne détecte pas les Windows reparse points (junctions)
- P1-6 `users.create` paye le KDF avant le check uniqueness (DoS amplifier)
- P1-7 `_DebugLogMiddleware` chmod 0600 sur log file
- P1-8 `Settings.argon2id_*` floors plus bas que `core.constants` floors

### Frontend (P1) — B-P1

- P1-2 TanStack Query `retry: 1` masque les transient sidecar errors
- P1-4 Sliding TTL pas exposé côté client (drift serveur/client)
- P1-5 Cache TanStack Query pas reset au lock — leak metadata cross-session
- P1-6 Race condition Lock+Unlock <100ms
- P1-7 `window.confirm` au lieu de `<AlertDialog>` (a11y + theme break)
- P1-9 Fingerprint warning sans fingerprint affiché (mitigation ADR-0004)
- P1-10 Vérifier `tsconfig.node.json` types node

### Sécurité (P1+) — C-P1/P2

- P1-4 Tauri 2.1.1 + `tauri-plugin-fs` scope non limité
- P2-1 `_zero_fill` Python loop vs `ctypes.memset`
- P2-2 `verify_admin_password` retourne `bytes` immutable
- P2-3 `share_file` cap silencieux 10 MiB
- P2-4 `tempfile` prefix expose filename clair sur FS
- P2-5 `_DebugLogMiddleware` activable par env var
- P2-6 `MAX_OVERWRITE_PASSES = 35` Gutmann paranoid
- P2-7 CSP `connect-src http://127.0.0.1:*` wildcard
- P2-8 `pip-audit --ignore-vuln=CVE-2026-3219` sans tracking

### DevOps (P1+) — D-P1/P2

- P1-1 Pas de pre-commit hook PyInstaller dry-run
- P1-2 NFR-3 mesure le bundle SOURCE pas final (timing biaisé)
- P1-3 SmartScreen / Defender false-positive scan absent
- P1-4 9 PRs Dependabot ouvertes non triées
- P1-5 Job python matrix manque macOS
- P1-6 Pas de `cargo audit` Rust CVEs
- P2-1 Coverage gate sidecar 90% sans ADR
- P2-2 `filterwarnings=["error"]` masque PytestUnraisableExceptionWarning
- P2-3 CVE-2026-3219 sans tracking automatique
- P2-4 SBOM Rust manquant
- P2-5 `release.yml:131` allow-fallback dégrade frozen-lockfile
- P2-6 Smoke-installer ne lance pas le binary post-install
- P2-7 Pas de log rotation
- P2-8 Sentry / error tracking frontend absent
- P2-9 Storybook référencé devDependencies (CHANGELOG dit removed)

### Code Quality + UX (P1+) — E-P1/P2

- P1-1 `core/operations.py` 915 lignes (split en file/message/share/\_streaming)
- P1-2 `encrypt_file`/`encrypt_message`/`share_file` partagent 70% scaffolding
- P1-3 16+ Python `Any` sans `# noqa: typing`
- P1-4 9 `# type: ignore` sidecar (typer User: User pour share.py 6×)
- P1-5 4× linear scan `users.list_all()` au lieu de `get_by_id`
- P1-6 Skeletons absents (juste "Chargement…" `<p>` flat)
- P1-7 Pas de system notification ni success animation sur encrypt
- P1-8 `BackgroundAurora` non memoisé (re-render sur chaque keystroke)
- P1-9 Empty `catch {}` blocks avec comment-as-rule-bypass (Biome)
- P1-10 `tests/e2e/` vide sauf `__init__.py` ; CLAUDE.md §7 mandate encrypt/decrypt/share E2E
- P1-11 Workaround `exactOptionalPropertyTypes` répété 2× sans extraction
- P1-12 Inline imports business logic (`unicodedata`, `time`)
- P1-13 Naming `*Modal` mais render `<article>` (pages routées, pas modales)
- P2-1 `BackgroundAurora` oklch literals au lieu des CSS tokens
- P2-2 `useDoctor(false, true)` boolean params
- P2-3 `next-themes` loaded never consumed
- P2-4 `biome.json` files.ignore stale
- P2-5 `biome.json` rules `warn` au lieu de `error`
- P2-6 `AuditVerifyResponse` ≡ `AuditVerifyView` duplicate
- P2-7 `BackgroundAurora` dupliqué App.tsx + lock.tsx
- P2-8 README claims "Tray + shortcuts" + "Glassmorphism + WebGL" non shippés
- P2-9 README binary size claim ≈15 MB vs réalité 6.3+41.7+45.7 MiB
- P2-10 `_DebugLogMiddleware` défini avant les imports projet (PEP 8)
- P2-11 Spec naming inconsistent ("000-" prefix pour 4 specs puis 001-002)
- P2-13 `dashboard.tsx` `navItems` reconstruit à chaque render
- P2-14 ADR-0017 "candidate" CHANGELOG mais fichier absent

## 5. Conformité ADR — synthèse

| ADR                            | Verdict synthétique                                                                  | Source     |
| ------------------------------ | ------------------------------------------------------------------------------------ | ---------- |
| ADR-0001 Tauri+sidecar         | Respecté archi ; "Hardened by default" partiellement faux (P0-β)                     | C          |
| ADR-0002 AES-GCM dual-KDF      | Respecté, floors+ceilings stricts                                                    | A, C       |
| ADR-0004 RSA-OAEP-4096 hybrid  | **Mitigation OOB neutralisée GUI** (B-P1-9 fingerprint pas affiché)                  | B, C       |
| ADR-0005 Vite over Next        | Respecté                                                                             | B          |
| ADR-0011 cross-platform DB     | **Déviation silencieuse** (P0-ι), audit_log columns non chiffrées (P1-5 sécu)        | A, C, D    |
| ADR-0012 PyInstaller now       | Respecté avec dette honnête                                                          | D          |
| ADR-0013 .crypt v1 format      | Respecté                                                                             | A, C       |
| ADR-0014 chunk-bound AAD       | **Respecté**                                                                         | A, C, E    |
| ADR-0015 anti-oracle stderr    | Respecté core+HTTP, mais **fallthrough non-422** côté front (P0-7 frontend)          | A, B, C, E |
| ADR-0016 sidecar IPC           | **§D non respecté** (P0-α), **§I CORS doc fausse** (P0-dd), §A/B/C/E/F/G/H respectés | A, B, C, D |
| ADR-0017 frontend state split  | **Fichier inexistant** (CHANGELOG "candidate")                                       | B, E       |
| ADR-0018 Authenticode dev cert | Respecté CI gating                                                                   | C, D       |

## 6. Verdict global avant soutenance

GuardiaBox est **structurellement plus mature qu'un projet académique GCS2
typique**. Le crypto core est senior-level. La discipline ADR + threat
model + NFR_VERIFICATION dépasse largement l'attendu CDC.

Les 22 P0 dédupliqués sont **réels mais largement de surface UX et de
surface code-review**, pas des trous crypto. Le jury qui scanne le
code va trouver 3-5 catches faciles (capabilities `:default`, deps
mortes, App.tsx, ADR-0011 dérive) ; le jury qui ne scanne pas va vivre
les UX bugs (BootSplash, Failed-to-fetch, init sans confirm).

**Tier A + items 6+7 du Tier B** (~10 h) ferme les deux types de
catches simultanément et te laisse 14 h de marge pour Phase J (J-01
relecture CDC, J-07 screenshots, J-08 bilan, J-09 répétitions, J-10
synthèse).

À toi de décider la priorisation finale. Je suis prêt à exécuter
n'importe quel tier en mode acceptEdits dès que tu valides.

=== AUDIT FINAL COMPLETE ===
