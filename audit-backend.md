# Audit Backend (A) -- 2026-04-29

## Executive Summary

Le backend GuardiaBox est solide sur le périmètre crypto pur (AES-GCM streaming + chunk-bound AAD ADR-0014, KDF floors+ceilings, anti-oracle stderr ADR-0015 sur `/decrypt`+`/accept`). Cinq écarts P0 doivent être traités **avant la soutenance** : (1) `/api/v1/secure-delete` accepte un path absolu arbitraire sans aucun `resolve_within` -- DoD-erase de `/etc/passwd` possible avec le launch token ; (2) `encrypt_message` n'applique pas la normalisation NFC alors que l'inverse `decrypt_message` la fait, footgun documenté comme corrigé ; (3) `users.delete` cascade FK déclarée `ON DELETE SET NULL` mais `PRAGMA foreign_keys` n'est jamais activé -- les vault_items / shares deviennent orphelins silencieusement ; (4) `vault.lock` lit `session_id` du body sans `require_session`, n'importe qui ayant le launch token peut clore une session arbitraire ; (5) `ADR-0011 SQLCipher Linux` est mort -- `database.py` rejette tout autre URL que `sqlite+aiosqlite`, contradiction avec docs/THREAT_MODEL/CRYPTO_DECISIONS qui annoncent encore SQLCipher comme baseline Linux. Aucune CVE crypto ouverte ; les chemins anti-oracle sont byte-identiques côté HTTP. Tests `test_decrypt_anti_oracle_byte_identical` ✅, mais aucune assertion timing.

## Findings P0 (critique, fix avant soutenance)

### P0-1 -- `/api/v1/secure-delete` -- file-deletion primitive non bornée

- **File** : `src/guardiabox/ui/tauri/sidecar/api/v1/secure_delete.py:60-87`
- **Description** : Le router accepte `body.path` sans appeler `resolve_within(target, root=settings.data_dir)`. Le core `secure_delete` (`src/guardiabox/core/secure_delete.py:137`) fait `path.resolve(strict=True)` mais aucun garde de containment. Un attaquant qui compromet la WebView2 (XSS local) ou intercepte le launch token peut DoD-effacer n'importe quel fichier que le process sidecar peut écrire (`%USERPROFILE%`, fichiers utilisateur, projets, etc.). Le SSD-confirm gate (line 66-74) ne protège QUE contre l'effet placebo wear-levelling, pas contre l'attaque path.
- **Impact** : **destruction de données arbitraires** sur la machine utilisateur. STRIDE = Tampering critique. AD-2 réaliste sous notre threat model.
- **Fix proposé** :
  ```python
  # secure_delete.py router, after `target = Path(body.path)` :
  from guardiabox.fileio.safe_path import resolve_within
  try:
      target_safe = resolve_within(target, settings.data_dir)
  except (PathTraversalError, SymlinkEscapeError) as exc:
      raise HTTPException(400, "path validation failed") from exc
  ```
  Ajouter un dep `settings_dep` (déjà importé ailleurs). Idem pour `/inspect`, `/encrypt`, `/decrypt` qui utilisent `root=source.parent` plutôt que `data_dir`.

### P0-2 -- `encrypt_message` ne normalise pas le password en NFC

- **File** : `src/guardiabox/core/operations.py:307`
- **Description** : Ligne 307 fait `kdf_impl.derive(password.encode("utf-8"), ...)`. Toutes les autres opérations (`encrypt_file:240`, `decrypt_file:369`, `decrypt_message:431`) passent par `_password_bytes(password)` qui NFC-normalise. Un message encrypté avec password `café` (U+00E9 précomposé) ne sera pas décrypté avec le même password tapé `café` (e + U+0301 combining). Le CHANGELOG.md ligne 372-374 annonce explicitement ce fix comme livré -- il est incomplet sur cette branche.
- **Impact** : **silent data loss** côté utilisateur macOS (NFD natif). L'encrypt réussit, le decrypt échoue, ANTI_ORACLE_MESSAGE collapse vers "decryption failed" -- l'utilisateur croit son password mauvais et peut perdre l'accès.
- **Fix proposé** :
  ```python
  # operations.py:307
  -        derived = kdf_impl.derive(password.encode("utf-8"), header.salt, AES_KEY_BYTES)
  +        derived = kdf_impl.derive(_password_bytes(password), header.salt, AES_KEY_BYTES)
  ```
  Ajouter un test `test_encrypt_message_nfc_roundtrip` qui chiffre avec NFC et déchiffre avec NFD.

### P0-3 -- `vault.lock` non protégé par `require_session`

- **File** : `src/guardiabox/ui/tauri/sidecar/api/v1/vault.py:144-149`
- **Description** : `POST /api/v1/vault/lock` lit `session_id` du **body** (`LockRequest`) au lieu du header `X-GuardiaBox-Session`. Le décorateur n'appelle pas `require_session`. Un attaquant détenant le launch token (= légitimement le shell Tauri sous le current trust model, mais aussi tout malware ayant lu le handshake stdout depuis `\\.\pipe\` sur Windows ou `/proc/<pid>/fd/0` sur Linux) peut force-close n'importe quelle session en posté son `session_id`. Le store retourne 204 silencieusement (`store.close` line 134 de `state.py`).
- **Impact** : DoS / forcer auto-lock. Pas de leak de secret, mais viole le principe "lock implique consentement utilisateur". Couplé avec la rate-limit absente sur `/lock` (BUCKET_WRITE 60/min), un attaquant peut tester 60 session_ids par minute -- ne mène à rien d'utile (entropie 256 bits) mais reste une primitive DoS.
- **Fix proposé** :
  ```python
  @router.post("/lock", status_code=status.HTTP_204_NO_CONTENT)
  def lock(
      session: Annotated[VaultSession, Depends(require_session)],
      store: Annotated[SessionStore, Depends(_store)],
  ) -> None:
      store.close(session.session_id)
  ```
  Supprimer le schema `LockRequest`. Le session_id doit ne JAMAIS apparaître dans un body JSON.

### P0-4 -- FK cascades déclarés mais `PRAGMA foreign_keys` jamais activé

- **File** : `src/guardiabox/persistence/database.py:73-78` (engine factory) + `src/guardiabox/persistence/migrations/versions/20260424_0001_initial_schema.py:55-56,79-93,109-113`
- **Description** : Les schemas déclarent `ON DELETE CASCADE` (vault_items.owner_user_id, shares.\*) et `ON DELETE SET NULL` (audit_log.actor_user_id). Mais SQLite désactive les FK par défaut (`PRAGMA foreign_keys = OFF`). `database.py:create_engine` ne fait aucun `connect_args={"detect_types": ..., "timeout": ...}` ni `event.listen(engine, "connect", ...)` pour activer le pragma. **Aucune cascade ne se produit** :
  - `delete user` laisse les vault_items et shares orphelins.
  - L'audit_log conserve `actor_user_id` pointant sur un user inexistant (acceptable pour l'historique, mais incohérent vs le schema).
  - Le test `test_user_delete_flow_removes_user_and_audits` passe précisément parce que les FK sont OFF -- l'attempt UPDATE sur audit_log par cascade SET NULL serait sinon bloquée par le trigger `audit_log_no_update`.
- **Impact** : Silent orphan rows. Forensic intégrité OK pour audit_log (l'append-only trigger protège), mais vault_items / shares cleanup est **muet** -- les fichiers `.crypt` deviennent unreachable via la DB mais persistent sur disque. Couplé au crypto-erase métadata-erase advertised par ADR-0011, c'est une régression silencieuse vs la spec 004 Phase B2.
- **Fix proposé** :

  ```python
  # database.py
  from sqlalchemy import event

  def create_engine(database_url: str, *, echo: bool = False) -> AsyncEngine:
      ...
      engine = create_async_engine(...)
      @event.listens_for(engine.sync_engine, "connect")
      def _enable_fks(dbapi_conn, _):
          cursor = dbapi_conn.cursor()
          cursor.execute("PRAGMA foreign_keys = ON")
          cursor.close()
      return engine
  ```

  PUIS résoudre le conflit cascade-trigger : soit changer `audit_log.actor_user_id` FK de `SET NULL` à NO ACTION (préserve forensique), soit modifier le trigger pour autoriser les UPDATE de `actor_user_id NULL`. ADR-of-supersession requis.

### P0-5 -- ADR-0011 SQLCipher Linux n'est plus livré

- **File** : `src/guardiabox/persistence/database.py:68-72`
- **Description** : Le check `if not database_url.startswith("sqlite+aiosqlite"):` rejette `sqlcipher+aiosqlite`. Le module docstring (ligne 7-11) reconnaît honnêtement la dérive : _"Phase C runs on a single async driver path... ADR-0011 documents the original SQLCipher-or-fallback strategy ; the async codebase settled on the fallback path"_. **Mais** :
  - `docs/CRYPTO_DECISIONS.md` §6.1 : "Linux (default) — SQLCipher AES-256-CBC with HMAC-SHA512..."
  - `docs/THREAT_MODEL.md` §6 + §4.4 : annonce SQLCipher comme baseline Linux.
  - `docs/ARCHITECTURE.md` ligne 169-173 : tableau des storage backends mentionne SQLCipher Linux par défaut.
  - ADR-0011 §"Concrete implementation roadmap" : `try: import sqlcipher3 → returns SQLCipher-backed engine`.
    Le code livre column-level AES-GCM **partout** (Linux + Windows + macOS). C'est un downgrade de défense profondeur silent vs les docs.
- **Impact** : Linux dev/server : pas de protection des B-tree indices, slack space, free pages. Backups SQLite rotatés par cron exposent les structures internes (les filenames sont chiffrés au niveau colonne, OK ; mais les index hmac sont des fingerprints stables qui permettent du tracking). Plus important : claim de soutenance non aligné avec implémentation.
- **Fix proposé** : deux options :
  - **A** (post-MVP) : restaurer le routing dual : `try: import sqlcipher3 ; engine = create_async_engine("sqlcipher+aiosqlite:///{path}", connect_args={"key": admin_pw_hex})`.
  - **B** (avant soutenance, plus rapide) : update `docs/CRYPTO_DECISIONS.md`, `docs/THREAT_MODEL.md`, `docs/ARCHITECTURE.md`, ADR-0011 pour refléter le shipping path réel. ADR-of-supersession sur ADR-0011 documentant pourquoi column-level uniformisé partout.

## Findings P1 (important, post-soutenance early)

### P1-1 -- RSA private key DER tenue en `bytes` immutable, jamais zero-fill

- **File** : `src/guardiabox/security/keystore.py:161-183` (`unlock_rsa_private` retourne `bytes`) ; `src/guardiabox/ui/tauri/sidecar/api/v1/share.py:139-141, 211-214`
- **Description** : `unlock_rsa_private` retourne `bytes` (immutable). Dans `share.py`, le DER est ensuite passé à `load_private_key_der(rsa_private_der)` -- pyca instancie un `RSAPrivateKey` C-context, mais le `bytes` source persiste jusqu'au GC. Aucun `bytearray + zero_fill` autour. Le master_key dérivé est bien zero-fillé dans `_derive_master_key`/`unlock_rsa_private`, mais le **payload** unwrappé (le DER PKCS8) ne l'est pas.
- **Impact** : Defense-in-depth violation vs CLAUDE.md §6 ("zero-fill key buffers post-use"). Un attaquant cold-boot ou debugger peut extraire le PKCS8 DER de la heap. THREAT_MODEL §4.5 documente honnêtement cette limite côté Python pour les bytes immutables, mais ici on a le levier de copier dans un bytearray + wipe-on-finally.
- **Fix proposé** : faire retourner `bytearray` à `unlock_rsa_private` (et adapter `load_private_key_der`/`accept_share`/`share_file` pour accepter bytes-like + drop la ref ASAP). Ou wrap dans un `with _zero_fill_after(rsa_private_der_buf):` context manager.

### P1-2 -- `bootstrap.init_vault` -- admin_key non zero-fill

- **File** : `src/guardiabox/persistence/bootstrap.py:127-139`
- **Description** : `admin_key = derive_admin_key(config, password)` retourne `bytes` (cf. `vault_admin.py:225`). Passé à `append(session, admin_key, ...)`, jamais zero-fillé. La fonction sort, GC reclame quand il veut.
- **Fix proposé** : convertir en `bytearray`, wrap try/finally + zero-fill à la fin de `init_vault`.

### P1-3 -- Décorateurs slowapi non appliqués sur les routes

- **File** : `src/guardiabox/ui/tauri/sidecar/api/rate_limit.py:1-69` + tous les routers
- **Description** : `limiter` est instancié, le `RateLimitExceeded` handler est branché (`app.py:170`), MAIS aucun routeur n'utilise `@limiter.limit(BUCKET_AUTH_UNLOCK)` sur `/vault/unlock`, `/users/{id}/unlock`, etc. Le CHANGELOG ligne 213 reconnaît "Per-route decorators land in a follow-up". ADR-0016 §D justifie 5/min sur unlock comme la "load-bearing" garde brute-force ; en l'état elle n'existe pas. Au PBKDF2 600k iter, ~1.5 attempt/sec = 90/min sur dev hardware, soit 100x au-dessus du floor.
- **Impact** : Brute-force unlock non bridé. Attaquant local-process avec le launch token peut tester 90 passwords/min. Sur un zxcvbn-3 password (~35 bits), expected crack window descend de 13 000 ans (ADR-0016) à ~600 ans -- toujours acceptable mais la marge déclarée n'est pas tenue.
- **Fix proposé** : ajouter `@limiter.limit(BUCKET_AUTH_UNLOCK)` sur `vault.unlock` et `users.unlock` (quand il atterrira). FastAPI exige `request: Request` dans la signature pour que slowapi puisse extraire le client IP.

### P1-4 -- `audit.encrypt_target` HMAC computé sans liaison à la séquence

- **File** : `src/guardiabox/persistence/repositories.py:369-381` (encrypt_target) + `src/guardiabox/security/audit.py:206-218`
- **Description** : `target_enc` AAD = `audit_log.target` + sequence (good, ciphertext lifting détecté). MAIS `target_hmac = deterministic_index_hmac(key, column="audit_log.target", plaintext=target_bytes)` -- aucune liaison à `sequence` dans le HMAC. Conséquence : deux audit rows avec le même `target` (e.g. deux secure-delete du même filename) ont **le même HMAC**. C'est l'usage explicite du HMAC index (lookup égalité), donc c'est conscient. Mais c'est aussi un fingerprint stable qui permet à un attaquant DB-read d'identifier les rows partageant le même target sans connaître le plaintext.
- **Impact** : Faible. STRIDE = Information Disclosure marginal (pattern matching). Acceptable per le design ADR-0011.
- **Fix proposé** : aucun urgent. Ajouter une note dans THREAT_MODEL §6 sur la propriété "deterministic HMAC = stable fingerprint, intentional for index lookup".

### P1-5 -- `secure_delete` core ne détecte pas les Windows reparse points

- **File** : `src/guardiabox/core/secure_delete.py:140-141`
- **Description** : `if resolved.is_symlink(): raise ValueError(...)`. Sur Windows, `is_symlink()` ne détecte que les vrais symlinks ; les junctions (`mklink /J`), volume mount points et OneDrive placeholders portent `IO_REPARSE_TAG_MOUNT_POINT` (≠ symlink tag). `safe_path.py` documente précisément ce point et utilise `_FILE_ATTRIBUTE_REPARSE_POINT` (0x400) ; `secure_delete` ne réutilise pas cette helper.
- **Impact** : Junction pointant vers un fichier vault -> overwrite + unlink suit le reparse, l'attaquant se débarrasse d'un fichier alors qu'il croit en effacer un autre. Fenêtre étroite (suppose attaquant filesystem-write).
- **Fix proposé** :
  ```python
  # secure_delete.py:140
  -    if resolved.is_symlink():
  -        raise ValueError(f"refusing to secure-delete a symlink: {resolved}")
  +    from guardiabox.fileio.safe_path import _is_reparse_point
  +    if _is_reparse_point(resolved):
  +        raise ValueError(f"refusing to secure-delete a reparse point: {resolved}")
  ```
  Promouvoir `_is_reparse_point` en API publique de `safe_path` (le `_` underscore est trompeur).

### P1-6 -- `users.create` paye le coût KDF avant le check uniqueness

- **File** : `src/guardiabox/ui/tauri/sidecar/api/v1/users.py:118-128`
- **Description** : Ordre : `keystore.create(password)` (ligne 119, paie PBKDF2 600k ou Argon2id 64 MiB) PUIS `repo.get_by_username(body.username)` (ligne 126). Un attaquant qui spam `/users` avec un username déjà pris fait perdre ~250-500ms KDF par requête (BUCKET_CRUD = 30/min limit, mais decorator pas branché P1-3). DoS amplifier.
- **Fix proposé** : inverser l'ordre :
  ```python
  async with open_db_session(settings) as db:
      repo = UserRepository(db, bytes(session.admin_key))
      existing = await repo.get_by_username(body.username)
      if existing is not None:
          raise HTTPException(409, "username already taken")
      try:
          new_keystore = keystore.create(body.password.get_secret_value())
      except WeakPasswordError as exc:
          raise HTTPException(400, str(exc)) from exc
      ...
  ```

### P1-7 -- `_DebugLogMiddleware` actif si env var `GUARDIABOX_DEBUG_LOG=1`

- **File** : `src/guardiabox/ui/tauri/sidecar/app.py:33-73, 184-186`
- **Description** : Quand activé, écrit `%TEMP%/guardiabox-sidecar.log` avec method + path + Origin + status + duration. Le path n'inclut pas la query string Starlette via `request.url.path`, donc le `?token=...` du WebSocket auth N'EST pas loggé. **Mais** :
  - Ligne 56 : `except Exception as exc: noqa: BLE001 nosec B902` -- catch-all + log de `type(exc).__name__: {exc}`. Si une exception interne contient une partie de payload sensible dans `str(exc)`, ça atterrit dans le log.
  - Le path `/api/v1/vault/unlock` répété N fois log + une attaque rate-limit révèle la séquence d'unlock failures.
  - Pas de chmod 0600 sur le log file.
- **Impact** : feature dev-only documentée. Un user qui set `GUARDIABOX_DEBUG_LOG=1` en prod expose ses paths. Acceptable hors-scope soutenance.
- **Fix proposé** : ajouter au docstring "DEV ONLY -- never set in production builds" + `_log_path.chmod(0o600)` après création.

### P1-8 -- `Settings.argon2id_*` floors plus bas que `core.constants` floors

- **File** : `src/guardiabox/config.py:21-23`
- **Description** : `argon2id_memory_cost_kib: ge=19_456` (~19 MiB) vs `ARGON2_MIN_MEMORY_KIB=64*1024` (64 MiB). Idem `time_cost: ge=2` vs `MIN=3`. Pas réellement exploitable car `Argon2idKdf()` rejette les valeurs <core floors. Mais c'est une incohérence qui peut induire en erreur (utilisateur qui set env var croit la limite à 19 MiB).
- **Fix proposé** : aligner `Field(default=65_536, ge=65_536)` et `time_cost: ge=3`. Idem `pbkdf2_iterations` est OK (`ge=600_000`).

## Findings P2 (nice-to-have)

### P2-1 -- `Argon2idKdf.derive` import `argon2.low_level` à chaque appel via dataclass

- **File** : `src/guardiabox/core/kdf.py:22, 154`
- **Description** : Le top-level `from argon2.low_level import Type, hash_secret_raw` est OK. Note CHANGELOG : "argon2-cffi 25.x compatibility (récemment cassé sur \_ffi)". Vérifier dans `pyproject.toml` que la version pin est >= 23.0 sinon `argon2.low_level` est fragile.

### P2-2 -- `ws.py` log des préfixes session_id

- **File** : `src/guardiabox/ui/tauri/sidecar/api/ws.py:72`
- **Description** : `session=session[:8] + "..."` -- expose 6 octets URL-safe = ~36 bits du session_id en log. Le session_id global est 256 bits, donc reste safe brute-force, mais l'invariant "ne JAMAIS logger un identifiant de session" est plus simple à grep.
- **Fix proposé** : remplacer par un hash tronqué `_log.info("stream.accepted", session_hint=hashlib.sha256(session.encode()).hexdigest()[:8])`.

### P2-3 -- `share_token` SIGNATURE_BYTES hardcodée à 512

- **File** : `src/guardiabox/core/share_token.py:104-105`
- **Description** : `SIGNATURE_BYTES: Final[int] = 512` (RSA-4096 modulus). Le `read_token` slice les 512 derniers bytes comme signature. Si un user crée un keystore avec `rsa_key_bits=3072` (autorisé par `Settings.rsa_key_bits: Literal[3072, 4096]`, config.py:24), la signature fait 384 bytes, le parser interprète mal le layout. Pas de check explicite que le keystore RSA = 4096.
- **Fix proposé** : soit forcer `Literal[4096]` côté Settings, soit retirer SIGNATURE_BYTES constant et lire la signature par calcul `key_size_bytes` au runtime.

### P2-4 -- `inspect_container` ne `resolve_within` pas

- **File** : `src/guardiabox/core/operations.py:133` + `src/guardiabox/ui/tauri/sidecar/api/v1/inspect.py:62`
- **Description** : `source.resolve(strict=True)` mais aucun garde sur la racine. L'endpoint `/inspect` peut donc inspecter n'importe quel `.crypt` sur disque. C'est par design (header public), mais expose `salt_hex` + `base_nonce_hex` -- public per ADR-0014, mais utile à un attaquant pour offline brute-force ciblé.

### P2-5 -- Tests anti-oracle ne mesurent pas le timing

- **File** : `tests/unit/test_sidecar_encrypt_decrypt.py:224-251`
- **Description** : `test_decrypt_anti_oracle_byte_identical` compare `r_wrong_pwd.content == r_tampered.content`. Pas d'assertion sur `elapsed_ms` ou wall-clock. Le timing oracle reste théoriquement ouvert (PBKDF2 toujours payé pour wrong-password ; le tag-check supplémentaire pour tamper diffère de quelques µs). Difficile à test deterministically -- acceptable.

### P2-6 -- `audit_log.audit_log_no_update` trigger ne bloque pas les reads ciphertext-substitution

- **File** : `src/guardiabox/persistence/migrations/versions/20260424_0001_initial_schema.py:128-145`
- **Description** : Le hash chain rattrappe la mutation row-level. Mais un attaquant DB-write peut INSERTer des rows à la fin de la chain (le trigger interdit UPDATE/DELETE, pas INSERT). Le `compute_entry_hash` requiert le `vault_admin_key` -- attaquant sans le master_key ne peut pas forger un `entry_hash` valide. **Acceptable** -- mais documenter dans THREAT_MODEL que la propriété "append-only" est défendue par triggers, pas la propriété "no spurious appends".

## Conformité ADR (TON périmètre)

- **ADR-0011** (cross-platform DB encryption) -> **DÉVIATION SILENCIEUSE** (cf. P0-5). Le shipping code livre column-level partout, les docs claim SQLCipher Linux. Justification : `database.py` docstring documente la dérive, mais les docs publiques ne suivent pas.
- **ADR-0014** (chunk-bound AAD) -> **respecté**. `core/crypto.py:chunk_aad` injecte `header_bytes || pack(!IB, index, is_final)`. `_encrypt_stream` lookahead-driven force `is_final=1` sur la dernière chunk, empty file emit one final-empty chunk (operations.py:481). `_decrypt_stream_plaintext` raise `DecryptionError` (anti-oracle compatible) sur missing final chunk (line 564).
- **ADR-0015** (anti-oracle stderr unification) -> **respecté côté core et HTTP**. `_log` events strippés (operations.py:374, 437). HTTP 422 + body identique pour DecryptionError ∪ IntegrityError (decrypt.py:142-145, share.py:236-240). Test byte-identical présent. **Mais** : `_DebugLogMiddleware` log les 401/422 status codes -- pas le payload, donc l'oracle reste fermé sur la wire ; le timing oracle reste théoriquement ouvert (P2-5).
- **ADR-0016** (Tauri sidecar IPC) -> **partiellement respecté**. ✅ : Bind 127.0.0.1 hard-coded `Literal`, token compare hmac.compare_digest, SessionStore TTL+slide+zero-fill, anti-oracle 422, schemas Pydantic v2 strict + frozen + extra=forbid, SecretStr passwords. ❌ : rate-limit decorators non appliqués (P1-3). ⚠️ : `vault/lock` ne require_session (P0-3).

Autres pertinents :

- **ADR-0002** (AES-GCM dual-KDF) -> respecté, floors et ceilings stricts (constants.py + kdf.py).
- **ADR-0004** (RSA-OAEP-SHA256 hybrid sharing) -> respecté, OAEP-SHA256 + PSS-MAX_LENGTH (`rsa.py:117-120, 207-210`).
- **ADR-0013** (.crypt v1 format) -> respecté. `read_header` valide magic, version, kdf_id, params length, salt length, base_nonce length avant tout dérivation (container.py:99-130).

## Quick wins (si tu en vois)

1. **Constant trivial** : `derive_admin_key` à `vault_admin.py:225` retourne `bytes` ; convertir en `bytearray` + plumb partout = +zero-fill discipline.
2. **Constant trivial** : `bootstrap.py:127` -- copier `admin_key` dans bytearray + zero-fill avant `engine.dispose()`.
3. **5 lignes** : ajouter `@event.listens_for("connect")` PRAGMA foreign_keys=ON dans `database.py` + adapter le trigger pour autoriser `actor_user_id NULL` UPDATEs (P0-4).
4. **1 ligne** : remplacer `password.encode("utf-8")` par `_password_bytes(password)` à `operations.py:307` (P0-2).
5. **Sync docs** : update `docs/THREAT_MODEL.md`, `docs/CRYPTO_DECISIONS.md`, `docs/ARCHITECTURE.md` pour refléter "column-level AES-GCM partout" (P0-5 option B).
6. **Promouvoir** `safe_path._is_reparse_point` en API publique (utilisé par `secure_delete`).
7. **Test** : `test_encrypt_message_nfc_roundtrip` (NFC encode + NFD decode round-trip) -- locks P0-2.
8. **Test** : `test_secure_delete_router_rejects_path_outside_data_dir` -- locks P0-1.

=== AUDIT COMPLETE ===
