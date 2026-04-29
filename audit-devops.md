# Audit DevOps / Build / QA (D) -- 2026-04-29

## Executive Summary

Pipeline et tests sont architecturalement solides (517 unit tests, gates `core/`+`security/` >= 95%, NSR-5 enforced, SBOM CycloneDX, Authenticode signing conditionnel) mais structurellement aveugles aux bugs runtime du bundle. Les 8 bugs catchés aujourd'hui sont tous le même pattern: chemins traversés UNIQUEMENT par `pnpm tauri build` puis exécution interactive du `.exe` -- jamais par les TestClient FastAPI ni par la matrice CI. Aggravant: aucune des 8 PRs de fix n'a ajouté de test de régression -- les 8 bugs peuvent revenir demain. Cargo.lock est gitignored (régression reproducibility), Playwright e2e existe mais n'est pas câblé en CI, smoke-test bundled binary ne hit que `/healthz`. Plan minimal pré-soutenance: 4 tests P0 + 1 script smoke-binary étendu.

## Post-mortem des 8 bugs runtime non catchés

Tous les 8 bugs sont survenus AVANT la soutenance et ont été fixés par PR #43 à #49. Aucun de ces fixes n'a ajouté de test de régression -- meta-finding majeur.

| #   | Bug                                              | Chemin runtime impliqué                      | Test qui aurait dû catch                                      | Pourquoi CI a raté                                                                                                                                                                                                                                           | Test concret à écrire                                                                                                                                                                                                                                                              |
| --- | ------------------------------------------------ | -------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | CORSMiddleware absent                            | Browser fetch tauri.localhost -> 127.0.0.1:N | Integration test simulant Origin header                       | TestClient (`tests/unit/test_sidecar_app.py:1-117`) ne fait jamais d'OPTIONS preflight, jamais de Origin: tauri.localhost. ADR-0016 §I disait "CORS Disabled" -- la spec elle-même était fausse                                                              | `tests/integration/test_sidecar_cors.py::test_options_preflight_from_tauri_localhost_succeeds` -- TestClient.options("/api/v1/vault/unlock", headers={"Origin":"http://tauri.localhost", "Access-Control-Request-Method":"POST"}) doit retourner 200 + Access-Control-Allow-Origin |
| 2   | Order LIFO middleware -> 500 sur OPTIONS         | TokenAuth voit OPTIONS sans token, crash     | Test OPTIONS preflight ANONYME (pas de token)                 | Aucun test n'envoie de OPTIONS au sidecar; les unit tests middleware (`tests/unit/test_sidecar_middleware.py:43-65`) testent GET protégés et whitelist mais pas OPTIONS                                                                                      | `tests/integration/test_sidecar_cors.py::test_options_preflight_does_not_require_token` -- valider explicitement que OPTIONS sur /api/v1/\* retourne 200 SANS X-GuardiaBox-Token                                                                                                   |
| 3   | PyInstaller --noconsole ferme stdout             | Bundled binary spawned par Tauri             | Smoke-test "bundled binary handshake" (cas Windows-noconsole) | `tests/integration/test_sidecar_subprocess.py:67` spawn le binary mais le build local n'avait pas l'option --noconsole testée. `--smoke-test` dans `scripts/build_sidecar.py:195-238` lit bien stdout mais le build CI utilise --release sans matrix Windows | Étendre `scripts/build_sidecar.py::_smoke_test` pour vérifier explicitement `proc.stdout` non-None et que la première ligne arrive sous 5s. Couplé à matrix Windows dans `release.yml` step `--smoke-test` qui actuellement ne tourne que sur la matrice (lignes 75)               |
| 4   | argon2-cffi 25.x retire `_ffi`                   | Bundled binary boot                          | Smoke-test bundled binary (boot)                              | `--hidden-import argon2._ffi` était un literal string dans `scripts/build_sidecar.py`. Aucun test ne vérifiait que `argon2.low_level` est importable depuis le bundle. Le smoke-test ne hit que `/healthz` qui n'invoque pas argon2                          | `tests/integration/test_sidecar_subprocess.py::test_sidecar_binary_imports_argon2_low_level` -- spawn binary, hit `/api/v1/init` (qui passe par argon2 si KDF=argon2id) ou un endpoint `/api/v1/_smoke_imports` qui force `import argon2.low_level`                                |
| 5   | Stderr Tauri non drainé -> uvicorn freeze 64 KiB | Tauri shell spawning sidecar                 | Cargo test parser handshake **avec stderr volumineux**        | `src/guardiabox/ui/tauri/src-tauri/src/sidecar.rs:240-274` teste parse_handshake() sur strings -- jamais de scenario où stderr déborde. Aucun test Rust ne spawn vraiment le sidecar                                                                         | `tests/integration/test_sidecar_stderr_drain.py::test_handshake_arrives_when_stderr_floods` -- spawn sidecar avec env GUARDIABOX_DEBUG_LOG=1 + stderr forcé > 64 KiB et confirmer que la première ligne stdout arrive bien                                                         |
| 6   | sidecar.rs path resolver triple suffix           | resolve_binary_path                          | Cargo unit test sur resolve_binary_path                       | Le code Rust (`sidecar.rs:121-181`) n'a aucun test unitaire pour `resolve_binary_path()` -- seul `parse_handshake` est testé. Le bug "Tauri strip triple" était documenté nulle part avant le fix                                                            | `src-tauri/src/sidecar.rs::tests::resolve_finds_stripped_form_in_resource_dir` -- mock de AppHandle.path().resource_dir() avec une fixture qui contient `guardiabox-sidecar.exe` ET vérifier qu'on retourne ce chemin avant `guardiabox-sidecar-x86_64-pc-windows-msvc.exe`        |
| 7   | Alembic versions/\*.py jamais bundlées           | sidecar boot -> migrate -> tables            | Smoke-test "bundled binary peut créer la DB"                  | `--collect-submodules guardiabox` bundle .pyc mais Alembic scanne le filesystem .py. `scripts/build_sidecar.py:171` ajoute maintenant `--add-data` mais aucun test ne vérifiait que les migrations SQL s'exécutaient depuis le binary bundlé                 | `tests/integration/test_sidecar_subprocess.py::test_bundled_binary_creates_users_table` -- spawn binary, init vault via /api/v1/init, créer un user via /api/v1/users (qui requiert table users), vérifier 201                                                                     |
| 8   | Frontend TS strict (Vite 7)                      | pnpm build                                   | Frontend job en CI                                            | Le job `frontend` (`ci.yml:116-166`) skip lint/typecheck/test si `pnpm-lock.yaml` absent. Le lockfile EST committed (commit `cd67143`) mais `pnpm-lock.yaml` n'a été committed qu'avec Phase I (`H-17 closes`). Avant ça le job était no-op                  | Renforcer la CI: `if: steps.lockfile.outputs.exists != 'true'` -> `error` dans `ci.yml:144-150` au lieu de warning silencieux                                                                                                                                                      |

**Meta-finding** : 0 / 8 PRs de fix ont ajouté un test de régression. Cf. `git show --stat 1d590a7 2a8b79b ce8734f 922115c b3e43d4 345bf64 29b3fab d5601fe` -- chacun ne touche que le code source qui contenait le bug. Le pre-commit hook `bandit`/`mypy`/`ruff` passe; rien ne force "fix doit ajouter test de régression".

## Findings P0 (critique, fix avant soutenance)

### P0-1 : 0/8 PRs de fix n'ont ajouté de test de régression

- **Files** : commits `1d590a7..922115c` (PR #43-#49)
- **Description** : Les 8 bugs runtime catchés aujourd'hui ont tous été corrigés par patch source uniquement. Aucune des 8 PRs n'a ajouté un test unitaire ou integration qui catche la régression. Demain ces 8 bugs peuvent revenir silencieusement.
- **Impact** : Garantie de récidive. La soutenance peut crasher sur un de ces 8 bugs si CI flake ou si dependabot bump retire à nouveau argon2.\_ffi (ex.).
- **Fix proposé** : 4 tests P0 minimaux à committer avant soutenance (cf. table post-mortem ci-dessus, lignes 1, 4, 7, 8). Estimation : 2h.

### P0-2 : Smoke-test bundled binary se limite à `/healthz`

- **File** : `scripts/build_sidecar.py:195-238` + `release.yml:74-75` + `tests/integration/test_sidecar_subprocess.py:67-106`
- **Description** : `_smoke_test()` parse handshake, hit `/healthz`, SIGTERM. Cela couvre les bugs #3 (stdout pipe) mais NON les bugs #4 (argon2.low_level qui n'est invoqué qu'au moment du KDF), #7 (Alembic non bundlé qui n'est invoqué qu'à `/api/v1/users` ou `/api/v1/init`), ni un share roundtrip end-to-end depuis le binary.
- **Impact** : Le binary peut "marcher" en CI (healthz 200) tout en étant cassé sur l'unlock réel. C'est exactement ce qui s'est passé avec le bug Alembic.
- **Fix proposé** : Étendre `scripts/build_sidecar.py::_smoke_test` (ou ajouter `scripts/smoke_bundled_binary.py`) pour exécuter un scenario complet. Cf. section "Plan smoke-test bundled binary" plus bas.

### P0-3 : Cargo.lock gitignored

- **File** : `src/guardiabox/ui/tauri/src-tauri/.gitignore:3` (`Cargo.lock`)
- **Description** : Pour une crate `[[bin]]` (application binary), Cargo.lock DOIT être committé selon les guidelines Rust officielles. Actuellement gitignored => Cargo regenere le lockfile à chaque build CI (`ci.yml:248-249` `cargo generate-lockfile if missing`), donc deux runs CI peuvent linker des versions transitives différentes. C'est précisément le cas où un dependabot bump tauri 2.1.1 -> 2.2.0 (cf. PR future) pourrait introduire silencieusement une régression de tauri-plugin-fs sans qu'on le voie.
- **Impact** : Build non-reproductible. Régression potentielle silencieuse sur les ~600 deps Rust transitives. Échec également du contrat NFR-9 implicite "verts pour chaque merge" -- "vert" n'a pas le même sens entre runs.
- **Fix proposé** : Retirer `Cargo.lock` de `src-tauri/.gitignore`, committer le lockfile présent (déjà 154 KiB local, généré le 21/04). Ajouter `cargo --locked` dans `ci.yml:255` à la place de `cargo clippy --all-features` pour enforcer.

### P0-4 : ADR-0016 §I "CORS Disabled" est techniquement fausse, jamais corrigée

- **File** : `docs/adr/0016-tauri-sidecar-ipc-security.md:157-162` + `src/guardiabox/ui/tauri/sidecar/app.py:188-216`
- **Description** : ADR-0016 §I dit "CORS Disabled. The only legitimate caller is the Tauri shell on the same origin via the loopback URL". Faux: Tauri 2 + WebView2 sert React depuis `tauri.localhost` tandis que le sidecar écoute `127.0.0.1:N` -- cross-origin garanti. Le bug #1 a été dû à cette ADR fausse. La PR #48 a ajouté CORS sans amender l'ADR.
- **Impact** : Source de vérité ADR diverge du code. Risque qu'un futur contributeur lise l'ADR, retire le CORS, et casse la production.
- **Fix proposé** : Ajouter une nouvelle ADR (`0019-cors-on-loopback.md`) qui supersede §I de 0016, ou amender 0016 directement avec un `### Update 2026-04-29` documentant la correction. ADR-0016 §I déjà commenté côté code (`app.py:188-200` "ADR-0016 sec I amended") mais l'ADR elle-même non touchée.

### P0-5 : Job CI `frontend` dégrade silencieusement quand pnpm-lock.yaml manque

- **File** : `.github/workflows/ci.yml:142-166`
- **Description** : Si `pnpm-lock.yaml` n'existe pas, le step "Detect lockfile" émet un `::warning` mais TOUS les autres steps (install/lint/typecheck/test) sont skippés via `if: steps.lockfile.outputs.exists == 'true'`. Le job rapporte vert sans avoir rien testé. C'est exactement comment le bug #8 (TS strict après Vite 7) a passé.
- **Impact** : Faux verts. Violation directe de §9bis CLAUDE.md "ne pas baisser une porte de qualité pour rendre le CI vert".
- **Fix proposé** : Remplacer le `::warning` par `exit 1` -- le lockfile EST maintenant committed (PR récente), donc l'absence est désormais une régression. Ligne 149 `echo "::warning ..."` -> `echo "::error ::pnpm-lock.yaml missing -- frontend gates cannot run"; exit 1`.

### P0-6 : Playwright e2e existe mais n'est jamais exécuté en CI

- **Files** : `src/guardiabox/ui/tauri/frontend/tests-e2e/smoke.spec.ts` + `playwright.config.ts` + `.github/workflows/ci.yml`
- **Description** : `tests-e2e/smoke.spec.ts` contient 1 seul test (heading visible). Le job `frontend` dans `ci.yml:116-166` ne lance JAMAIS `pnpm test:e2e`, juste `pnpm test` (vitest). Donc l'unique test e2e n'a jamais tourné en CI, jamais protégé du bug #1 (Failed to fetch sur unlock).
- **Impact** : Pyramide de tests manquante au sommet. Les bugs frontend -- sidecar comme #1, #2 et un futur bug similaire -- ne sont catchés par AUCUN test.
- **Fix proposé** : Activer `pnpm test:e2e` dans `ci.yml` derrière un `if: matrix.os == 'ubuntu-latest'` (Playwright peut driver Vite dev server, pas besoin de bundle Tauri). Au minimum 1 spec étendue: `lock_then_init.spec.ts` qui visite `/lock`, type un mot de passe, soumet le formulaire, vérifie redirection vers `/dashboard`. Estimation : 1h.

## Findings P1

### P1-1 : Aucun pre-commit hook PyInstaller dry-run

- **File** : `.pre-commit-config.yaml`
- **Description** : Les bugs #4 (argon2.\_ffi) et #7 (Alembic versions) auraient été catchés par un dry-run PyInstaller au commit-time. Pas de hook actuellement.
- **Fix proposé** : Hook custom `pyinstaller-dry-run` qui passe `pyinstaller --dry-run` ou bien `python -c "import argon2.low_level"` + `python -c "from alembic.script import ScriptDirectory"`. Coût : 5s par commit, justifié par les 8 bugs runtime.

### P1-2 : Job `nfr-verification` mesure le bundle SOURCE, pas le bundle final

- **File** : `.github/workflows/release.yml:223-286`
- **Description** : `verify_nfr.py --binary $sidecar_full_name --gui-binary $gui_full_name` mesure les artefacts standalone. Or NFR-3 GUI cold start doit refléter l'expérience utilisateur réelle: `Start-Process GuardiaBox.exe` (qui spawn ensuite le sidecar). La mesure actuelle spawn juste le sidecar standalone -- le timing ne reflète pas le lock-screen-first-paint réel sous Tauri.
- **Impact** : NFR-3 GUI publié à ~5700 ms peut être sous-estimé ou surestimé selon les couplages WebView2/sidecar. Le doc NFR_VERIFICATION.md:62 documente la limite, mais c'est pas une excuse.
- **Fix proposé** : Étendre `scripts/verify_nfr.py::_measure_gui_cold_start` pour spawn vraiment le `GuardiaBox.exe` et chronométrer jusqu'au moment où WebView2 émet un signal "ready" (via une route Tauri custom ou un IPC event).

### P1-3 : Pas de SmartScreen / Defender false-positive scan

- **File** : `release.yml`
- **Description** : ADR-0012 §"Cons" reconnaît que PyInstaller --onefile triggers Windows Defender false positives. ADR-0018 documente le signing self-signed comme mitigation partielle. Mais aucune étape CI ne mesure si le binary est bien identifié comme "signed but unknown publisher" vs "unrecognized" / "blocked".
- **Fix proposé** : Step optionnel `Get-MpThreatDetection -ScanPath $bundle` après l'install dans `smoke-installer`. Documenter le résultat dans `nfr-report.json`.

### P1-4 : 9 PRs Dependabot ouvertes non triées (#1-5, #9, #11, #13, #41)

- **File** : github.com/sachamarlov/crypto-sidecar/pulls
- **Description** : 4 PRs CI deps (actions/checkout v4 -> v6, codeql v3 -> v4, codecov v5 -> v6, setup-node v4 -> v6, pnpm/action-setup v4 -> v6), 5 PRs npm deps (testing group, tailwind-merge, react-three group, sonner). Stale depuis Phase H (avril).
- **Impact** : Surface CVE non triée + risque de breakage cumulé si on les merge en bulk juste avant soutenance.
- **Fix proposé** : Triage prioritaire pré-soutenance: merger #2-5 (GH actions, low-risk) en bulk via `gh pr merge --squash`. Différer #9, #11, #13, #41 (npm deps) au post-soutenance puisqu'aucune CVE flaggée par `pnpm audit` (cf. CHANGELOG).

### P1-5 : Job `python` matrix manque macOS

- **File** : `.github/workflows/ci.yml:31`
- **Description** : `matrix.os: [ubuntu-latest, windows-latest]`. Pas de macOS. ADR-0011 documente le path SQLCipher fallback colonnaire pour macOS, mais zéro test ne valide ce path. Le release.yml a bien macOS-13 + macOS-14, mais c'est trop tard.
- **Impact** : Régression silencieuse possible sur `persistence/database.py` macOS path.
- **Fix proposé** : Ajouter `macos-latest` à la matrix `ci.yml:31`. ~10 min runner billing supplémentaire par PR; gérer le user blocker billing GitHub Actions séparément (cf. doc NFR_VERIFICATION:195 "Unblock GitHub Actions billing"). Si billing bloque: au moins ajouter un `if: github.ref == 'refs/heads/main'` macos-only.

### P1-6 : Pas de `cargo audit` pour CVEs Rust

- **File** : `.github/workflows/ci.yml` job `rust:209-258`
- **Description** : `cargo fmt`, `cargo clippy -D warnings`, `cargo test`. Mais pas `cargo audit` (`rustsec/audit-check`). Or les ~600 deps Rust transitives Tauri+plugins sont une surface CVE.
- **Fix proposé** : Ajouter step `actions-rs/audit-check@v1` après clippy. Coût : 30s.

## Findings P2

### P2-1 : Coverage gate sidecar = 90% sans justification ADR

- **File** : `scripts/check_coverage_gates.py:30` + `docs/CONVENTIONS.md:127-128`
- **Description** : `core/` >= 95%, `security/` >= 95%, `ui/tauri/sidecar/` >= 90%. Pourquoi 5% en moins pour le sidecar? Pas d'ADR. CLAUDE.md §9bis "ne pas baisser un gate sans documenter".
- **Fix proposé** : Documenter dans `CONVENTIONS.md:127-128` ou ADR pourquoi 90%. Ou aligner à 95%.

### P2-2 : `filterwarnings = ["error"]` masque `PytestUnraisableExceptionWarning`

- **File** : `pyproject.toml:404-414`
- **Description** : Filter ajouté à cause de SQLAlchemy aiosqlite GC issues. Masque potentiellement de vraies erreurs de cleanup. Documenté en commentaire mais pas tracké dans une issue.
- **Fix proposé** : Ouvrir une issue "remove PytestUnraisableExceptionWarning filter" trackée pour SQLAlchemy 2.1+ release.

### P2-3 : `pip-audit --ignore-vuln=CVE-2026-3219` sans fixed-version tracking

- **File** : `.github/workflows/ci.yml:73-74`
- **Description** : Ignorer une CVE pip-only sans fix; commentaire dit "re-reviewed each CI touch" mais aucun mécanisme automatique.
- **Fix proposé** : Cron monthly `pip-audit --check-fixed CVE-2026-3219` qui ouvre un issue si la CVE a été patchée upstream.

### P2-4 : SBOM job ne génère pas de SBOM Rust

- **File** : `.github/workflows/release.yml:291-337`
- **Description** : SBOMs Python (cyclonedx-py) + npm (cyclonedx-npm). Pas de SBOM Rust (cargo-cyclonedx ou syft). Or les deps Rust représentent ~50% de la surface du bundle.
- **Fix proposé** : Ajouter `cargo install cargo-cyclonedx && cargo cyclonedx --output-format json --output-file sbom-rust.json` dans le job `sbom`.

### P2-5 : `release.yml:131` allow-fallback dégrade frozen-lockfile

- **File** : `.github/workflows/release.yml:131`
- **Description** : `pnpm install --frozen-lockfile || pnpm install` -- si le frozen install échoue (lockfile out-of-sync), on fallback sur un non-frozen install. C'est exactement le pattern §9bis "ne pas baisser un gate".
- **Fix proposé** : Retirer le `|| pnpm install`. Si frozen échoue, c'est le signal qu'il faut bumper le lockfile.

### P2-6 : Smoke-installer ne lance pas le binary post-install

- **File** : `release.yml:181-217`
- **Description** : Le smoke installer vérifie que GuardiaBox.exe est dans Program Files, mais ne le lance pas. Donc si le bundled binary crash au boot (bug #4 / #7), le smoke test passe.
- **Fix proposé** : Après le silent install, `Start-Process $exe.FullName ; Start-Sleep 5 ; Get-Process GuardiaBox` pour vérifier que le process tourne. Idéalement faire un `curl http://127.0.0.1:N/healthz` mais ça nécessite de récupérer le port Tauri.

### P2-7 : observabilité prod: pas de log rotation

- **File** : `src/guardiabox/logging.py` (non lu mais référencé) + `app.py:184-186` (`GUARDIABOX_DEBUG_LOG=1` -> `%TEMP%/guardiabox-sidecar.log`)
- **Description** : Le debug log est append-only sans rotation. Sur une session demo de plusieurs heures avec audit -- log peut grossir indéfiniment.
- **Fix proposé** : `RotatingFileHandler(maxBytes=10MB, backupCount=3)` ou un middleware structlog qui plafonne.

### P2-8 : Frontend Sentry / error tracking absent

- **File** : `src/guardiabox/ui/tauri/frontend/package.json:29-101`
- **Description** : Ni @sentry/react ni alternative offline-first. Si la WebView2 crash sur la machine du jury, pas de trace.
- **Fix proposé** : Considérer `react-error-boundary` (déjà installé) + une route `/api/v1/_log_frontend_error` qui pousse côté sidecar dans audit log. Out-of-scope pré-soutenance.

### P2-9 : Storybook retiré (CHANGELOG) mais reste référencé dans devDependencies

- **File** : `src/guardiabox/ui/tauri/frontend/package.json:123` (`"storybook": "^8.6.18"`)
- **Description** : CHANGELOG dit "Storybook removed entirely (last `uuid` moderate via `@storybook/addon-actions`). The project never wrote a single `*.stories.*` file in Phase H". Mais `storybook` est encore listé comme devDependency. Probable oubli.
- **Fix proposé** : `pnpm remove storybook` + bump le lockfile.

## Plan smoke-test bundled binary (proposition concrète)

Créer `scripts/smoke_bundled_binary.py` orchestré comme suit. À intégrer dans `release.yml` après `tauri` job (avant `nfr-verification`):

```python
# scripts/smoke_bundled_binary.py
"""Full lifecycle smoke test on the bundled PyInstaller sidecar binary.

Spawns the binary, drives a complete vault lifecycle, asserts at every step.
Exits 0 on success, non-zero with diagnostic on failure.

Used post-bundle in release.yml to catch the class of bugs the unit/integration
tests cannot see (PyInstaller hidden-import gaps, Alembic versions/ data files,
stderr drain, etc.).
"""

import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx

BINARY = Path(sys.argv[1])  # bundled .exe
TIMEOUT = 30  # seconds total
ADMIN_PWD = "Smoke_Test_Admin_42!"
USER_PWD = "Smoke_Test_User_44!"


def main() -> int:
    proc = subprocess.Popen(
        [str(BINARY)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"GUARDIABOX_DATA_DIR": str(Path(tempfile.mkdtemp(prefix="gbox_smoke_")))},
    )
    try:
        # 1. Handshake within 10s
        line = proc.stdout.readline().decode().strip()
        assert line.startswith("GUARDIABOX_SIDECAR="), f"bad handshake {line!r}"
        port_str, token = line.removeprefix("GUARDIABOX_SIDECAR=").split(" ", 1)
        port = int(port_str)
        time.sleep(0.5)

        with httpx.Client(timeout=10.0, headers={"X-GuardiaBox-Token": token}) as c:
            base = f"http://127.0.0.1:{port}"
            # 2. Healthz
            assert c.get(f"{base}/healthz").status_code == 200

            # 3. Init vault (CATCHES Alembic migrations missing)
            r = c.post(f"{base}/api/v1/init", json={"admin_password": ADMIN_PWD})
            assert r.status_code == 201, f"init failed: {r.status_code} {r.text}"

            # 4. Unlock + grab session_id (CATCHES argon2.low_level missing)
            r = c.post(f"{base}/api/v1/vault/unlock", json={"admin_password": ADMIN_PWD})
            assert r.status_code == 200, r.text
            session_id = r.json()["session_id"]
            c.headers["X-GuardiaBox-Session"] = session_id

            # 5. Create user (CATCHES users table missing)
            r = c.post(f"{base}/api/v1/users", json={"username": "smoker", "password": USER_PWD})
            assert r.status_code == 201, r.text
            user_id = r.json()["user_id"]

            # 6. Encrypt + decrypt roundtrip (CATCHES crypto path issues)
            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
                f.write(b"smoke test payload")
                src = f.name
            r = c.post(f"{base}/api/v1/encrypt",
                       json={"path": src, "password": USER_PWD, "kdf": "pbkdf2"})
            assert r.status_code == 200, r.text
            crypt = r.json()["output_path"]

            r = c.post(f"{base}/api/v1/decrypt",
                       json={"path": crypt, "password": USER_PWD})
            assert r.status_code == 200, r.text

            # 7. Anti-oracle: wrong password must yield 422 with constant body
            r = c.post(f"{base}/api/v1/decrypt",
                       json={"path": crypt, "password": "wrong"})
            assert r.status_code == 422
            assert r.json() == {"detail": "decryption failed"}

            # 8. CORS preflight (CATCHES the bug #1+#2 class)
            r = c.options(f"{base}/api/v1/vault/unlock",
                          headers={"Origin": "http://tauri.localhost",
                                   "Access-Control-Request-Method": "POST",
                                   "Access-Control-Request-Headers": "X-GuardiaBox-Token"})
            assert r.status_code == 200, f"CORS preflight failed: {r.status_code}"
            assert "tauri.localhost" in r.headers.get("access-control-allow-origin", "")

        print("[smoke] ALL CHECKS PASSED", file=sys.stderr)
        return 0
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    sys.exit(main())
```

Wiring dans `release.yml` après job `tauri`, avant `nfr-verification`:

```yaml
smoke-bundled-sidecar:
  name: Smoke bundled sidecar lifecycle
  needs: sidecar
  runs-on: ${{ matrix.os }}
  strategy:
    matrix:
      os: [ubuntu-latest, windows-latest]
  steps:
    - uses: actions/checkout@v4
    - uses: astral-sh/setup-uv@v4
    - run: uv python install 3.12 && uv sync
    - uses: actions/download-artifact@v4
      with:
        name: guardiabox-sidecar-${{ matrix.os == 'windows-latest' && 'x86_64-pc-windows-msvc' || 'x86_64-unknown-linux-gnu' }}
        path: ./bin
    - shell: bash
      run: |
        chmod +x ./bin/guardiabox-sidecar-* 2>/dev/null || true
        BIN=$(ls ./bin/guardiabox-sidecar-* | head -1)
        uv run python scripts/smoke_bundled_binary.py "$BIN"
```

Coût CI estimé : ~2 min par OS × 2 = 4 min total. Bénéfice : aurait catché 5/8 bugs d'aujourd'hui (#1, #2, #4, #7, et indirectement #3 via le `proc.stdout.readline()` qui timeout si --noconsole).

## Conformité ADR (périmètre DevOps)

| ADR                                             | Sujet                                                          | Verdict                         | Détails                                                                                                                                                                                                                                                             |
| ----------------------------------------------- | -------------------------------------------------------------- | ------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **ADR-0011** (cross-platform DB)                | Strategy SQLCipher Linux + AES-GCM colonnaire fallback Win/Mac | **Conforme avec dette**         | `pyproject.toml:73` bien `sqlcipher3-binary ; sys_platform == 'linux'`. Mais aucun test ne valide le path colonnaire fallback (cf. P1-5 macos manquant). Conforme à 90%.                                                                                            |
| **ADR-0012** (PyInstaller now, Nuitka post-CDC) | Path migration Nuitka acceptance criteria                      | **Conforme**                    | `scripts/build_sidecar.py` PyInstaller-only, ADR-0012 §"Concrete invariants 2" mentionne le ticket de migration Nuitka. NFR_VERIFICATION:46-47 documente la dette CLI cold-start. Pas de Nuitka encore (post-CDC).                                                  |
| **ADR-0016** (sidecar IPC)                      | Token, session, anti-oracle, slowapi, no CORS                  | **Déviation §I non documentée** | §I "CORS Disabled" est faux dans la réalité (cf. P0-4). Le fix #48/#49 a corrigé le code mais l'ADR n'a pas été amendée. Toutes les autres sections (§A token, §B session, §C anti-oracle, §D slowapi, §G bind 127.0.0.1 enforced via Literal type) sont conformes. |
| **ADR-0018** (Authenticode)                     | Self-signed dev cert, gated CI signing, demo-machine prep      | **Conforme**                    | `release.yml:151-168` step Sign gated sur `WINDOWS_CERT_PFX_BASE64`. `signtool verify /pa /v` après chaque sign (`release.yml:166`). Conforme. Notable: la rotation du cert (1 an d'expiry) est trackée comme follow-up dans l'ADR -- pas d'automation.             |

## Quick wins (impact / effort favorable, < 1h chacun)

1. **Committer Cargo.lock** (P0-3) -- 5 min : `git rm --cached` impossible (déjà gitignored), donc retirer l'entrée du `.gitignore`, `git add Cargo.lock`, commit. Build reproductible immédiat.
2. **Activer `pnpm test:e2e` en CI** (P0-6) -- 30 min : ajouter step dans `ci.yml frontend` + une 2e spec `tests-e2e/lock_screen.spec.ts`.
3. **Failer le job frontend si pnpm-lock manquant** (P0-5) -- 5 min : 1 ligne dans `ci.yml:149`.
4. **Amender ADR-0016 §I** (P0-4) -- 15 min : 5 lignes de markdown documentant la correction CORS sans toucher au code.
5. **Merger les 4 PRs Dependabot GH-Actions** (P1-4) -- 10 min : `gh pr merge 2 3 4 5 --squash` après vérification CI verte.
6. **Retirer Storybook** (P2-9) -- 2 min : `pnpm remove storybook`.
7. **Ajouter `cargo audit`** (P1-6) -- 10 min : 1 step dans `ci.yml rust`.
8. **Test CORS preflight unit** (P0-1 partiel) -- 15 min : 1 fichier `tests/integration/test_sidecar_cors.py` couvrant bugs #1 et #2.

Total quick wins : ~1h30 cumulé, catche 6/8 bugs d'aujourd'hui en régression et amende le contrat ADR.

=== AUDIT COMPLETE ===
