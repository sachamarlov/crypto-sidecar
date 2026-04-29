# Audit Sécurité Offensive (C) -- 2026-04-29

## Executive Summary (5 lignes max)

Audit offensive READ-ONLY de GuardiaBox v0.1.0 à T-1 de la soutenance.
La crypto core est solide (AES-GCM streaming, AAD chunk-bound ADR-0014, anti-oracle
ADR-0015 propagé sur HTTP). **MAIS** plusieurs ADRs sont rédigés et non tenus
dans le code: rate-limit ADR-0016 §D non décoré (brute-force unlock illimité),
capabilities Tauri en `*:default` bundles (CLAUDE.md §11 violé), CSP `'unsafe-inline'`
sur styles, `devtools` activé en release, NFC-normalisation absente sur
`encrypt_message`, vault.admin.json non signé. **3 P0 + 5 P1 + 8 P2** identifiés.

## Findings P0 (critique, fix avant soutenance)

### P0-1 — Rate-limiter slowapi déclaré mais aucune route décorée: brute-force /vault/unlock illimité

- **STRIDE**: Elevation of Privilege / Denial of Service / Information Disclosure
- **File**:
  - `src/guardiabox/ui/tauri/sidecar/api/rate_limit.py:14-17` (constants déclarés)
  - `src/guardiabox/ui/tauri/sidecar/app.py:167-170` (limiter binding mais pas de route décorée)
  - `src/guardiabox/ui/tauri/sidecar/api/v1/vault.py:95-142` (`/unlock` SANS `@limiter.limit`)
  - `src/guardiabox/ui/tauri/sidecar/api/v1/share.py` (idem pour `/accept` et `/share`)
  - `src/guardiabox/ui/tauri/sidecar/api/v1/encrypt.py` (idem pour `/encrypt`)
  - `src/guardiabox/ui/tauri/sidecar/api/v1/decrypt.py` (idem pour `/decrypt`)
- **Description**: ADR-0016 §D verrouille la stratégie défensive sur le brute-force du
  `/vault/unlock` (5/min). Le module `rate_limit.py` définit les constantes
  `BUCKET_AUTH_UNLOCK = "5/minute"`, `BUCKET_WRITE = "60/minute"` etc. et expose
  `limiter`. `app.py` enregistre `app.state.limiter = limiter` et le handler
  `RateLimitExceeded`. **MAIS aucun routeur n'applique `@limiter.limit(...)`**.
  Recherche grep exhaustive: 0 décorateur appliqué dans `api/v1/`. Le commentaire
  de `rate_limit.py:17` parle de "router decorators apply `@limiter.limit(...)` lazily"
  mais ils ne le font pas. CHANGELOG mentionne "G-11.b: per-route slowapi decorators land
  in a follow-up" — la "follow-up" n'a jamais été merge.
- **Exploit scenario**:
  1. Attaquant local non-priviligié (AD-2) `netstat -ano` → trouve le port loopback du sidecar.
  2. `ReadProcessMemory` sur `guardiabox.exe` ou `guardiabox-sidecar.exe` → token de session 32 octets
     extractible (cf. P0-2). Alternative: spawn d'un processus enfant héritant du `STDOUT_HANDLE`
     du sidecar avant la lecture du handshake.
  3. Avec le token: brute-force `/api/v1/vault/unlock` à débit max (en pratique limité par
     PBKDF2-SHA256 600k iter ≈ 250 ms/tentative sur CPU moderne).
  4. À 4 attempts/sec × 86 400 sec = ~345 600 tentatives/jour. zxcvbn ≥ 3 ≈ 2^35
     entropie → 2^35 / 345 600 ≈ 100 000 jours. **MAIS**: ADR-0016 calcule
     "13 000 ans" en supposant 5 attempts/min — réalité 1 200× plus rapide. Et les passwords
     dictionnaire (zxcvbn=3 sur des phrases communes) tombent en quelques heures sans rate-limit.
- **Impact**:
  - Brute-force du master password admin → unlock complet du vault (clé d'admin = clé column-level
    de toutes les colonnes chiffrées → username, filenames, audit metadata).
  - DoS trivial (50k req/sec sur PBKDF2 → CPU 100% sidecar).
  - Violation directe de l'invariant clé d'ADR-0016 §D ("CWE-307 — Improper restriction of excessive auth attempts").
- **Fix proposé**: Sur chaque endpoint sensible, ajouter le décorateur:
  ```python
  @router.post("/unlock", ...)
  @limiter.limit(BUCKET_AUTH_UNLOCK)
  def unlock(request: Request, body: ..., ...):  # request param requis par slowapi
      ...
  ```
  Test E2E: 6e tentative en moins de 60s renvoie `429`.

### P0-2 — Capabilities Tauri massivement en `*:default` bundles + `devtools` en release

- **STRIDE**: Elevation of Privilege / Information Disclosure
- **File**:
  - `src/guardiabox/ui/tauri/src-tauri/capabilities/default.json:7-37` (32 permissions, dont 9 `*:default` bundles)
  - `src/guardiabox/ui/tauri/src-tauri/Cargo.toml:23` (`tauri = { version = "2.1.1", features = ["devtools"] }`)
  - `src/guardiabox/ui/tauri/src-tauri/tauri.conf.json:13` (CSP avec `style-src 'self' 'unsafe-inline'`)
- **Description**: CLAUDE.md §9bis et §11 INTERDISENT explicitement le remplacement
  des permissions granulaires par `<plugin>:default` bundles ("Forbidden moves include:
  Replacing a granular permission set with `<plugin>:default` bundles"). Or
  `default.json` contient: `core:default`, `core:webview:default`, `core:event:default`,
  `core:image:default`, `core:menu:default`, `core:tray:default`, `core:resources:default`,
  `core:path:default`, `fs:default`, `notification:default`, `store:default`,
  `window-state:default`. Surface d'attaque inconnue, non auditable. Le bundle
  `fs:default` notamment ouvre l'API FS Tauri à toute la `homeDir` selon les versions
  de tauri-plugin-fs. Et `tauri = { features = ["devtools"] }` est laissé activé en
  build release (devrait être `cfg(debug_assertions)` only).
- **Exploit scenario**:
  1. Si un script malicieux est injecté dans React (via XSS, supply-chain compromise d'une dep —
     cf. P1-3, ou via `'unsafe-inline'` styles + un `style="background:url(javascript:...)`),
     il peut directement appeler `invoke('plugin:fs|read_text_file', { path: '/Users/.../passwords.txt' })`
     ou `invoke('plugin:dialog|open', { ... })` pour exfiltrer.
  2. `devtools` activé en production → un attaquant qui obtient un accès renderer
     peut ouvrir DevTools, inspecter `localStorage` (langue, thème, mais aussi les
     `sessionId` Jotai persistés? À vérifier), modifier le CSP runtime, etc.
- **Impact**: Un seul XSS rend tout le vault exfiltrable. La défense en profondeur
  prônée par ADR-0001 ("Hardened by default — Tauri's allowlist + CSP eliminate the
  most common Electron-style escape vectors") est annulée par les `*:default`.
- **Fix proposé**:
  - Remplacer chaque `*:default` par la liste explicite des permissions effectivement utilisées
    (ex: `core:webview:allow-show`, `fs:allow-read-text-file` SANS scope global, etc.).
  - `Cargo.toml`: `tauri = { version = "2.1.1", features = [] }` en release;
    activer `devtools` derrière `[features.dev-tools] tauri = { features = ["devtools"] }`.
  - CSP: retirer `'unsafe-inline'` de `style-src` (utiliser nonces ou `unsafe-hashes` ciblé).

### P0-3 — `vault.admin.json` non signé/HMAC: substitution silencieuse possible

- **STRIDE**: Tampering / Spoofing / Denial of Service
- **File**:
  - `src/guardiabox/security/vault_admin.py:259-281` (`write_admin_config` / `read_admin_config`)
  - `src/guardiabox/security/vault_admin.py:114-160` (`to_json` / `from_json`)
- **Description**: `vault.admin.json` contient `salt`, `kdf_id`, `kdf_params`, `verification_blob`.
  Le commentaire ligne 19-20 affirme "The JSON file is **not** a secret: the salt and
  KDF parameters are public inputs". CORRECT pour la confidentialité — INCORRECT pour
  l'intégrité. **Aucun MAC ni signature n'authentifie le fichier**. Le `verification_blob`
  est un AES-GCM de `VERIFICATION_PAYLOAD` sous la clé admin: il prouve seulement que
  _quelqu'un_ connaissait UN password capable de produire UNE clé qui scelle CE blob.
- **Exploit scenario** (AD-2, accès écriture sur `~/.guardiabox/vault.admin.json`):
  1. Attaquant remplace tout le fichier `vault.admin.json` par un nouveau qu'il a
     généré localement avec son propre password (`my-evil-pass` connu de lui seul).
     Le nouveau fichier contient un nouveau `salt`, nouveaux `kdf_params`, et un
     `verification_blob` valide pour `my-evil-pass`.
  2. Au prochain démarrage, l'utilisateur légitime tape son vrai mot de passe
     → DecryptionError sur le verification_blob → 401 "unlock failed". L'utilisateur
     pense qu'il a un bug, contacte le support, redémarre la machine, etc.
  3. Pendant que l'utilisateur est bloqué hors de son vault, l'attaquant peut
     déchiffrer le DB (les colonnes restent chiffrées sous l'ANCIENNE clé admin —
     SAUF s'il accède à la DB AVANT l'écrasement: alors il peut tout lire avec sa propre
     clé après écrasement? Non, les colonnes sont sealed sous l'ancienne clé).
  4. Variante: l'attaquant supprime juste le fichier → "vault not initialised" →
     l'utilisateur est invité à `init` → si l'utilisateur clique OK, écrase la DB existante.
     **Effacement silencieux du vault par DoS social-engineered**.
  5. Variante 2 (plus subtile): l'attaquant remplace UNIQUEMENT le `kdf_params`
     pour passer de PBKDF2 600k → 600k+1 iterations: la verification réussit (clé identique
     à 1 iter près n'est pas le cas — donc DoS), OU si l'attaquant met `kdf_id=2` (Argon2id)
     avec params crafted, il peut imposer m=64MiB chaque déverrouillage et ralentir le
     déverrouillage légitime (DoS amplifié).
- **Impact**: DoS du vault, perte de données (variante 4), confusion utilisateur,
  attaques de phishing facilitées.
- **Fix proposé**: Sceller le fichier avec un MAC dérivé d'une clé secondaire
  stockée (et chmod 0600) à part, OU au minimum sceller avec une signature
  Authenticode-like utilisant la machine TPM. Solution la plus simple compatible
  avec les contraintes existantes: stocker le SHA-256 du fichier dans un emplacement
  alternatif chmod 0600 (ex: `vault.admin.json.sha256`) et vérifier au lancement.

## Findings P1

### P1-1 — `encrypt_message` n'applique PAS NFC-normalisation au password (incohérence avec encrypt_file)

- **STRIDE**: Information Disclosure (cohérence cryptographique brisée)
- **File**: `src/guardiabox/core/operations.py:307`
- **Description**: `encrypt_file` (ligne 240) et `decrypt_file` (ligne 369) appellent
  `_password_bytes(password)` qui normalise NFC avant UTF-8.
  `decrypt_message` (ligne 431) appelle aussi `_password_bytes`.
  **`encrypt_message` (ligne 307) appelle directement `password.encode("utf-8")`**
  SANS normalisation NFC. Le CHANGELOG affirme "Passwords NFC-normalised before UTF-8
  encoding to prevent visually-identical codepoint sequences from deriving distinct keys."
  → invariant non tenu sur `encrypt_message`.
- **Exploit scenario**:
  1. Utilisateur français saisit password contenant un `é` sur clavier macOS configuré
     en NFD (rare mais possible: input methods CJK/coréen aussi). Sur encrypt: pas
     de normalisation → clé dérivée K_NFD.
  2. Sur decrypt (où NFC est appliqué): clé dérivée K_NFC ≠ K_NFD → DecryptionError.
  3. Le message est désormais **inrécupérable** par l'utilisateur légitime sans manuellement
     deviner que le password subit une normalisation différente.
- **Impact**: Perte de données silencieuse pour utilisateurs internationaux. Bug
  cryptographique réel: encrypt et decrypt ne sont pas inverses pour certains
  passwords.
- **Fix proposé**: Remplacer ligne 307 par `_password_bytes(password)`. Test
  property-based: `decrypt_message(encrypt_message(m, p), p) == m` pour `p` arbitraire
  Unicode (hypothesis avec `unicode` strategy générant codepoints NFD/NFC).

### P1-2 — Sidecar resolve_within "passe-partout": `root=source.parent` accepte n'importe quel path absolu

- **STRIDE**: Path Traversal / Tampering / Information Disclosure
- **File**:
  - `src/guardiabox/ui/tauri/sidecar/api/v1/encrypt.py:118-119` (`root=source.parent`)
  - `src/guardiabox/ui/tauri/sidecar/api/v1/decrypt.py:121` (`root=source.parent`)
- **Description**: ADR-0016 §H ("Path fields are validated post-hoc by the router
  via `resolve_within` inside the `Settings.data_dir` root"). Or les routeurs
  encrypt/decrypt passent `root=source.parent`. **Le root est dynamiquement
  l'ancêtre direct du fichier source**, donc `resolve_within(source, source.parent)`
  est trivialement passant — le source résout TOUJOURS dans son propre parent.
  Et `resolve_within(dest, source.parent)` ne contrôle pas que `dest` reste
  sous `Settings.data_dir` — il contrôle juste que dest est sous la même directory
  que source. Si l'attaquant fournit `path = "C:/Windows/System32/config/SAM"`,
  le routeur traite SAM comme source, et `dest` peut être n'importe où sous
  `C:/Windows/System32/config/`.
- **Exploit scenario**:
  1. Frontend compromis (cf. P0-2) appelle `POST /api/v1/encrypt` avec
     `{"path": "C:/Users/victim/Documents/secret.docx", "password": "...",
  "dest": "C:/Users/victim/Public/secret.docx.crypt", "force": true}`.
  2. Le sidecar valide qu'il existe, dérive une clé sous le password attaquant,
     écrit `secret.docx.crypt` dans `Public/`. Variante: source dans `Public/`,
     dest dans le dossier attaquant.
  3. **Pire**: `POST /api/v1/decrypt` avec un path arbitraire → écriture de plaintext
     décrypté dans n'importe quel dossier, y compris des dossiers système
     (UAC permettant) ou des dossiers où l'utilisateur ne s'attend pas à trouver
     son plaintext (fuite via les caches Windows comme `Recent\` etc.).
- **Impact**: Sortie de plaintext hors du vault root configuré, contournement de
  l'invariant `Settings.data_dir`. La présence de la garde `safe_target == source_resolved`
  dans `core/operations.py` n'aide pas car le source EST contrôlé par l'attaquant.
- **Fix proposé**: Routeur:
  ```python
  vault_root = settings.data_dir.resolve()
  source_resolved = resolve_within(source, vault_root)  # refuse si hors vault
  if dest_path:
      dest_resolved = resolve_within(dest_path, vault_root)
  ```
  Plus restrictif: ajouter une whitelist explicite (`Documents`, `Downloads`, vault).

### P1-3 — `@noble/ciphers` + `@noble/hashes` en deps frontend mais NON IMPORTÉS (CLAUDE.md §11 violation)

- **STRIDE**: Tampering (supply chain), Information Disclosure (debt cryptographique)
- **File**: `src/guardiabox/ui/tauri/frontend/package.json:31-32`
- **Description**: CLAUDE.md §11 interdit "Importing crypto code in `ui/` layers
  directly (always go through `core/`)". Les deps `@noble/ciphers ^1.0.0` et
  `@noble/hashes ^1.6.0` sont déclarées en `dependencies` (pas devDependencies)
  et sont donc bundlées dans le release frontend. Recherche d'imports: `grep -rn
"@noble" src/guardiabox/ui/tauri/frontend/src/` → 0 résultat. Ces librairies
  sont présentes dans le bundle final mais non utilisées.
- **Exploit scenario**: Si une vulnérabilité est trouvée dans `@noble/ciphers`
  ≥1.0.0 (transitive) ou en `1.0.0` lui-même: arrivée silencieuse, surface
  d'attaque inutile. Plus subtilement, leur présence dans le bundle donne à un
  attaquant compromettant le frontend (cf. P0-2) une primitive crypto déjà chargée
  pour exfiltrer chiffré, ou pour ré-implémenter du AES-GCM côté UI bypassant le sidecar.
- **Impact**: Surface d'attaque inutile (~80 KiB bundle gonflé), violation directe
  de l'invariant CLAUDE.md §11.
- **Fix proposé**: `pnpm remove @noble/ciphers @noble/hashes` puis vérifier que
  `pnpm build` passe et que le bundle réduit.

### P1-4 — Tauri 2.1.1 pinning et tauri-plugin-fs scope non limité

- **STRIDE**: Elevation of Privilege
- **File**: `src/guardiabox/ui/tauri/src-tauri/Cargo.toml:23` (`tauri = "2.1.1"`)
  - `capabilities/default.json:23` (`fs:default`)
- **Description**: `fs:default` du plugin `tauri-plugin-fs` 2.0.3 inclut par défaut
  un large scope (`$APPDATA`, `$RESOURCE`, `$HOME` selon doc Tauri). Combiné
  à un XSS, lecture/écriture libre de `~/.guardiabox/`, `%APPDATA%/GuardiaBox/`,
  voire `$HOME/Documents/`. Pas de scope explicite défini dans capabilities.
- **Fix proposé**: Définir un scope explicite via:
  ```json
  {
    "identifier": "fs:scope",
    "allow": [{ "path": "$APPDATA/GuardiaBox/**" }]
  }
  ```

### P1-5 — Audit log non chiffré au repos (Win/Mac sans SQLCipher): action + actor + timestamp + hash chain visibles

- **STRIDE**: Information Disclosure / Repudiation
- **File**: `src/guardiabox/persistence/migrations/versions/20260424_0001_initial_schema.py:104-123`
  - `src/guardiabox/persistence/database.py:42-49` (`sqlcipher_available()` purement informatif)
- **Description**: ADR-0011 promet "filenames and audit metadata are never on disk
  in plaintext". Réalité: la table `audit_log` chiffre `target_enc` et `metadata_enc`
  par AES-GCM column-level. **MAIS** les colonnes `sequence`, `timestamp`,
  `actor_user_id`, `action`, `prev_hash`, `entry_hash` sont stockées EN CLAIR.
  Le code (`database.py:73`) crée TOUJOURS un engine `sqlite+aiosqlite` standard
  (pas SQLCipher) — la branche SQLCipher n'est même plus exposée (l'extra
  `sqlcipher-source` n'est plus testé en CI). `sqlcipher_available()` est purement
  informatif.
- **Exploit scenario**: AD-2 lit `~/.guardiabox/vault.db` directement avec sqlite3:
  - Voit toutes les actions: `file.encrypt`, `file.share`, `user.unlock_failed`...
  - Voit les timestamps précis → cartographie comportementale.
  - Voit `actor_user_id` (UUID) → corrélation entre users.
  - Peut DROPPER les triggers `audit_log_no_update` / `audit_log_no_delete`
    car ils ne sont app-side que.
  - Peut MODIFIER une row → `verify_audit_chain()` dans le sidecar détectera
    au prochain check, mais l'attaquant peut juste supprimer la row et
    recompute la chain depuis ce point.
- **Impact**: Forensic post-incident dégradé. Repudiation possible (action ne
  laissant aucune trace immutable hors process running). ADR-0011 et THREAT_MODEL §6
  ne mentionnent pas cette dégradation honnêtement.
- **Fix proposé**: Forcer SQLCipher en sidecar binary (le binary embarque déjà
  cryptography + argon2-cffi, ajouter sqlcipher3-binary dans le PyInstaller bundle).
  Alternativement: chiffrer aussi les colonnes `action`, `actor_user_id`, `timestamp`.

## Findings P2

### P2-1 — `_zero_fill` pure-Python boucle byte-par-byte vs ctypes.memset (best-effort documenté mais perfectible)

- **STRIDE**: Information Disclosure (memory residency)
- **File**: `src/guardiabox/core/operations.py:637-639`, `src/guardiabox/security/keystore.py:288-290`
- **Description**: `_zero_fill(buf)` itère en boucle Python `for i in range(len(buf)): buf[i] = 0`. Le compilateur CPython peut optimiser ces accès mais ne garantit pas que le secret soit effectivement écrasé en RAM (l'interpréteur peut stocker des intermédiaires temporaires). THREAT_MODEL §4.5 documente honnêtement ce caveat. La feuille de route mentionne `ctypes.memset` comme prochaine étape — non implémenté.
- **Fix proposé**: `import ctypes; ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(buf)), 0, len(buf))` pour bypass JIT/optims.

### P2-2 — `verify_admin_password` retourne `bytes` immutable, jamais zero-fillable

- **STRIDE**: Information Disclosure
- **File**: `src/guardiabox/security/vault_admin.py:228-256` + `vault.py:112,134-137`
- **Description**: La fonction renvoie `candidate_key` qui est `bytes` (kdf.derive output) — Python l'immutabilise. Le routeur `vault.py:134-137` fait `del admin_key` mais le copy interne dans `AESGCM` (utilisé pour le verification) reste vivant jusqu'à GC. THREAT_MODEL §4.5 le mentionne.
- **Fix proposé**: Convertir en `bytearray` plus tôt, garder dans la SessionStore.

### P2-3 — `share_file` reads source via `decrypt_message` qui cap à 10 MiB silencieusement

- **STRIDE**: Denial of Service (UX-cliff) / Information Disclosure (timing)
- **File**: `src/guardiabox/core/operations.py:753` + `share_token.py:99-102`
- **Description**: Sharing un fichier > 10 MiB lève `MessageTooLargeError` après que le password ait été validé et le KDF tourné. Information disclosure: le timing différencie "fichier OK petit" / "fichier trop gros" / "wrong password". Acceptable mais non documenté dans ADR-0015.

### P2-4 — `tempfile.NamedTemporaryFile` prefix = `.{path.name}.` expose le nom du fichier en clair sur le système de fichiers

- **STRIDE**: Information Disclosure
- **File**: `src/guardiabox/fileio/atomic.py:49-55`
- **Description**: Le temp file pour atomic writer est nommé `.report.pdf..xxxx.tmp.gbox` (préfixe = filename d'origine). Pendant que decrypt streame, le filesystem expose ce nom temporairement. Un attaquant pollant `~/.guardiabox/` ou le dossier de destination peut voir quels fichiers sont en cours de traitement.
- **Fix proposé**: Préfixe random `.guardiabox.tmp.{uuid4().hex}` au lieu de path.name.

### P2-5 — `_DebugLogMiddleware` activable par env var en prod (GUARDIABOX_DEBUG_LOG=1)

- **STRIDE**: Information Disclosure
- **File**: `src/guardiabox/ui/tauri/sidecar/app.py:33-73, 184-186`
- **Description**: Quand `GUARDIABOX_DEBUG_LOG=1`, chaque requête est loggée dans `%TEMP%/guardiabox-sidecar.log` avec method + path + Origin + status + duration. Pas de gating prod/dev. Le log file n'est pas chmod 0600. Si un attaquant peut setter cette env var (write `~/.profile` ou `setx GUARDIABOX_DEBUG_LOG 1`) il obtient un trace complet du comportement utilisateur sans token compromis.

### P2-6 — `MAX_OVERWRITE_PASSES = 35` accepte des values absurdes (Gutmann paranoid)

- **STRIDE**: Denial of Service
- **File**: `src/guardiabox/core/secure_delete.py:59`
- **Description**: 35 passes × 64 KiB blocks × `secrets.token_bytes` random = consommation CPU/I/O lourde pour un usage attaqué. `passes=35` sur un fichier 1 GiB = ~35 GiB d'I/O random. Acceptable comme cap mais pas exposé en API d'une façon qui justifie 35 (l'utilisateur doit explicitement le demander).

### P2-7 — CSP `connect-src` autorise `http://127.0.0.1:*` (tous ports)

- **STRIDE**: Information Disclosure
- **File**: `src/guardiabox/ui/tauri/src-tauri/tauri.conf.json:13`
- **Description**: Un script malicieux dans le bundle React peut fetch n'importe quel service local listening sur loopback (Redis, Postgres dev, autres apps Electron) — exfiltration latérale. ADR-0016 §I documente la décision mais le wildcard `*` est plus large que nécessaire.
- **Fix proposé**: Au runtime, après handshake, tighten `connect-src` à `http://127.0.0.1:<actual-port>` via meta tag dynamique.

### P2-8 — `pip-audit --ignore-vuln=CVE-2026-3219` (pip CVE silencieusement skippé en CI)

- **STRIDE**: Tampering (supply chain debt)
- **File**: `.github/workflows/ci.yml:74`
- **Description**: CVE-2026-3219 sur pip lui-même skippé. Documenté en commentaire mais devrait être tracké avec un ticket de sortie d'ignore quand le fix sera dispo.

## Matrice STRIDE actualisée

| Threat                                            | Category | Mitigation in code                                                                               | Status  |
| ------------------------------------------------- | -------- | ------------------------------------------------------------------------------------------------ | ------- |
| Token sidecar leakable (handshake stdout)         | S        | `main.py:75` flush atomique; Rust `sidecar.rs:96` lit 1ère ligne                                 | OK      |
| Brute-force unlock                                | S/E      | ADR-0016 §D rate-limit 5/min — **NON DÉCORÉ** sur routes (P0-1)                                  | **GAP** |
| Tauri renderer exfiltrating via FS                | E        | Capabilities granulaires — **violées par `*:default` bundles** (P0-2)                            | **GAP** |
| Container `.crypt` truncation/reorder/header-swap | T        | `core/crypto.py:94 chunk_aad` AAD = header_bytes \|\| (index, is_final) ADR-0014                 | OK      |
| AES-GCM tag verify constant-time                  | I        | `cryptography` lib AES-NI / `hmac.compare_digest`                                                | OK      |
| KDF DoS (crafted iter/memory)                     | D        | `core/constants.py:37,47,55,62` hard ceilings (10M, 1 GiB, 20, 16)                               | OK      |
| Anti-oracle wrong-password vs tampered-CT (CLI)   | I        | `core/operations.py:558-609` post-KDF → DecryptionError uniform; ADR-0015                        | OK      |
| Anti-oracle wrong-password vs tampered-CT (HTTP)  | I        | `api/v1/decrypt.py:135-145` 422 + constant body; `api/v1/share.py:233-240`                       | OK      |
| Path traversal (CLI)                              | T/I      | `fileio/safe_path.py:36 resolve_within` + `_reject_reparse_points_in_chain` (Win reparse points) | OK      |
| Path traversal (HTTP)                             | T/I      | Routes passent `root=source.parent` — **garde inopérante** (P1-2)                                | **GAP** |
| Source==dest                                      | T        | `core/operations.py:223-226, 357-360` `DestinationCollidesWithSourceError`                       | OK      |
| Source==dest case-insensitive Windows             | T        | `Path.resolve()` normalise, mais `==` est case-sensitive — **risque NTFS** non couvert           | DEBT    |
| vault.admin.json substitution                     | T/D      | Aucune signature/HMAC sur le fichier (P0-3)                                                      | **GAP** |
| audit_log append-only                             | T/R      | SQL triggers `audit_log_no_update/delete` mais bypassable hors process                           | DEBT    |
| audit_log non chiffré (Win/Mac default)           | I        | column-level encrypts target/metadata mais action/actor/timestamp en clair (P1-5)                | DEBT    |
| Memory zero-fill                                  | I        | `_zero_fill` Python loop (P2-1); THREAT_MODEL §4.5 honest                                        | DEBT    |
| Atomic temp file wipe on Ctrl+C                   | I        | `fileio/atomic.py:82-92 _best_effort_wipe_and_unlink` (Fix-1.N)                                  | OK      |
| Stderr leak (structlog)                           | I        | `core/operations.py:374-379` no log on decrypt failure; ADR-0015                                 | OK      |
| Sidecar bind 127.0.0.1 only                       | E        | `config.py:33 Literal["127.0.0.1"]` + test grep `0.0.0.0` (Fix-1.X)                              | OK      |
| Tauri devtools enabled in release                 | I/E      | `Cargo.toml:23` features=["devtools"] sans cfg debug (P0-2)                                      | **GAP** |
| `style-src 'unsafe-inline'`                       | T/E      | `tauri.conf.json:13` (P0-2)                                                                      | DEBT    |
| `connect-src http://127.0.0.1:*` wildcard         | I        | Trop large; pourrait être tightened post-handshake (P2-7)                                        | DEBT    |
| RSA-OAEP/RSA-PSS unwrap padding-oracle            | I        | `core/rsa.py:184-190` IntegrityError uniform; signature verify FIRST                             | OK      |
| Share token expiry post-signature                 | I        | `core/operations.py:868-872` `ShareExpiredError` AFTER verify                                    | OK      |
| WebSocket auth                                    | S/E      | `api/ws.py:52-69` constant-time token compare + session validation                               | OK      |
| Password NFC-normalisation encrypt_file           | I        | `_password_bytes` line 240/369                                                                   | OK      |
| Password NFC-normalisation encrypt_message        | I        | **Pas de normalisation** (P1-1)                                                                  | **GAP** |
| `secrets.token_bytes` for nonces/salts/DEKs       | I        | OS CSPRNG (`getrandom`/`BCryptGenRandom`)                                                        | OK      |
| Encrypt > 10 GiB DoS                              | D        | streaming, pas de cap autre que 32-bit chunk counter (256 TiB)                                   | OK      |
| `decrypt_message` MAX_BYTES (10 MiB cap)          | D        | `core/operations.py:418-423` enforce avant secret material read                                  | OK      |
| `decrypt_message` constant-time discriminator     | I        | Cap pré-KDF: timing diff "trop gros" vs "wrong password" (P2-3)                                  | DEBT    |
| `pip-audit` ignored CVE                           | T        | `ci.yml:74` skips CVE-2026-3219 sans tracking ticket (P2-8)                                      | DEBT    |

## Conformité ADR (tous, 0000-0018)

- **ADR-0000 (MADR v4)** → respecté. `docs/adr/0000-*.md` ouvre la série; format MADR cohérent.
- **ADR-0001 (Tauri 2 + Python sidecar)** → respecté pour l'archi. Mais "Hardened by default — Tauri's allowlist + CSP" promis et **partiellement faux** (cf. P0-2: capabilities en bundles `*:default`, devtools release).
- **ADR-0002 (AES-GCM + dual KDF)** → respecté. `core/constants.py` enforce floors AND ceilings ADR-extension.
- **ADR-0003 (SQLCipher)** → superseded par ADR-0011. Impl actuelle dégradée (cf. P1-5).
- **ADR-0004 (RSA-OAEP-SHA256 hybride)** → respecté. `core/rsa.py` + `share_token.py` cohérents avec ADR.
- **ADR-0005 (Vite over Next.js)** → respecté. Vite 7 (post-bump), pas de Next.
- **ADR-0006 (uv over Poetry)** → respecté. `uv.lock` committed.
- **ADR-0007 (Conventional Commits + release-please)** → respecté. CHANGELOG auto.
- **ADR-0008 (Spec-Driven Dev)** → respecté. `docs/specs/` existent.
- **ADR-0009 (fine-grained PAT)** → non vérifiable côté repo (config GitHub).
- **ADR-0010 (Apache 2.0)** → respecté. LICENSE présent.
- **ADR-0011 (cross-platform DB encryption)** → **partiellement respecté**. Column-level
  encrypt OK pour `target_enc`/`metadata_enc`/`username_enc`/`filename_enc`.
  **Déviation**: les colonnes `action`/`actor_user_id`/`timestamp` du audit_log
  restent en clair (P1-5). Le path SQLCipher Linux n'est plus testé.
  `database.py:42-49` `sqlcipher_available()` est informatif uniquement.
- **ADR-0012 (PyInstaller now, Nuitka post-CDC)** → respecté. NFR_VERIFICATION.md
  documente le gap honnêtement.
- **ADR-0013 (.crypt v1 format)** → respecté. `core/container.py` + `core/constants.py`
  cohérents (magic GBOX, version 0x01, KDF id, params len uint16, etc.).
- **ADR-0014 (chunk-bound AAD)** → respecté. `core/crypto.py:94 chunk_aad`
  exactement `header_bytes || pack("!IB", index, is_final)`.
- **ADR-0015 (anti-oracle stderr unification)** → respecté. `core/operations.py:558-609`
  - `api/v1/decrypt.py:135-145` + `api/v1/share.py:233-240` collapse uniformément.
    Test `tests/unit/test_cli_anti_oracle.py` via subprocess.
- **ADR-0016 (Tauri sidecar IPC security)** → **partiellement respecté**.
  - §A token transport: OK (`api/middleware.py` constant-time).
  - §B vault session: OK (`state.py SessionStore` zero-fill, sliding TTL).
  - §C anti-oracle: OK (cf. ADR-0015).
  - **§D rate-limit: NON RESPECTÉ — décorateurs absents (P0-1)**.
  - §E WebSocket: OK (`api/ws.py` query-string auth).
  - §F TLS-none on loopback: OK.
  - §G bind hard-coding: OK (Literal + grep test).
  - §H schemas strict + frozen: OK (Pydantic v2 ConfigDict).
  - **§I CORS disabled: NON RESPECTÉ** — `app.py:201-216` ajoute CORSMiddleware avec
    4 origins (`http://tauri.localhost`, `https://tauri.localhost`, `tauri://localhost`,
    `http://localhost:1420`). Justifié par le besoin Tauri 2 WebView2 mais c'est
    explicitement une "déviation amendée" non encore re-documentée dans l'ADR.
- **ADR-0017** → **MANQUANT**. CHANGELOG mentionne "ADR-0017 candidate" pour Jotai/Zustand
  state split mais aucun fichier `docs/adr/0017-*.md`. Trou dans la numérotation.
- **ADR-0018 (Authenticode dev cert)** → respecté en CI (`release.yml:151-168`).
  Limite assumée (SmartScreen warning hors machine demo). Conditional gate
  `if: env.WINDOWS_CERT_PFX_BASE64 != ''` correct.

## Top 5 surfaces d'attaque restantes (post-fix P0)

1. **Memory residency des secrets** (THREAT_MODEL §4.5 honnête): tant que `cryptography`
   AESGCM C-context vit, la clé reste en RAM accessible via `ReadProcessMemory`/`ptrace`.
   Mitigation finale = ctypes.memset OU mlock OU Rust crypto-side. Backlog.

2. **audit_log non chiffré au repos sans SQLCipher**: même après P1-5 fix, l'invariant
   ADR-0011 n'est pas tenu sur Win/Mac sans extra. Une seule ligne CI (`uv sync --extra
sqlcipher-source` sur Win runner) prouverait que la branche fonctionne.

3. **Frontend bundle compromission**: si une dep React (radix-ui transitive) introduit
   un XSS, P0-2 capabilities + P1-3 noble + P2-7 connect-src wildcard convergent en
   exfiltration totale. Mitigation = SRI sur le bundle + capabilities granulaires
   strictes + suppression noble + tightening connect-src post-handshake.

4. **vault.admin.json substitution offline**: même après P0-3 (signature/HMAC ext),
   un attaquant offline avec FDE désactivé peut reset le vault et regénérer
   l'ensemble. Mitigation OS-level: forcer BitLocker recommandé dans README.

5. **Brute-force inter-launch**: P0-1 fix bornera 5/min PAR LAUNCH. Un attaquant peut
   relancer le sidecar (kill + spawn) → reset rate limiter en mémoire. Mitigation =
   persister les attempts dans `users.failed_unlock_count` (déjà schema-side) +
   exponential backoff (la THREAT_MODEL §4.1 mentionne "Exponential backoff up to 15 min,
   never permanent lockout (BIP-39)" mais non implémenté côté code).

=== AUDIT COMPLETE ===
