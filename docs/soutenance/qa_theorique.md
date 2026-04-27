# Q&A théorique préparation (J-05)

20 questions probables, classées par catégorie. Pour chaque :
réponse 30-60 secondes + sources citables.

## Cryptographie

### Q1 — Pourquoi AES-GCM et pas AES-CBC + HMAC ?

GCM est un AEAD (Authenticated Encryption with Associated Data)
défini dans NIST SP 800-38D. Il bundle confidentialité +
intégrité en un seul passage. CBC + HMAC demande deux passes,
est fragile au padding-oracle (cf. Vaudenay 2002), et l'ordre
encrypt-then-MAC vs MAC-then-encrypt est un piège classique.
GCM est aussi accéléré matériel via AES-NI + CLMUL sur tous les
CPUs modernes. Choix imposé par le CDC, mais c'est aussi le
choix qu'on aurait fait. Référence : NIST SP 800-38D §6.

### Q2 — Pourquoi 600 000 itérations PBKDF2 ?

OWASP Password Storage Cheat Sheet 2026 recommande ≥ 600 000
itérations pour PBKDF2-HMAC-SHA256 dans un contexte FIPS-140.
À 600k, le coût pour cracker un password de score zxcvbn 3
(≈ 35 bits d'entropie) sur du hardware GPU consumer dépasse
$10 000 — soit plusieurs ordres de grandeur au-dessus du coût
de la donnée protégée. Le floor est durci dans
`core/constants.py:PBKDF2_MIN_ITERATIONS` à la fois sur encode
et decode (cf. Fix-1.C, plafond DoS guard).

### Q3 — Argon2id m=64 MiB t=3 p=1 : d'où viennent ces valeurs ?

OWASP Cheat Sheet 2026 pour des appareils interactifs avec ≥
1 Go de RAM. RFC 9106 §4 donne des recommandations équivalentes.
m=64 MiB pour la résistance GPU (les cartes ont peu de SRAM par
core), t=3 pour amortir les attaques side-channel cache, p=1
pour rester déterministe sur single-threaded servers.

### Q4 — Que se passe-t-il si un nonce GCM est réutilisé ?

Catastrophe : on peut récupérer la clé de hashing GHASH (forge
de tag arbitraire) et XORer les ciphertexts pour obtenir le XOR
des plaintexts (canal d'information massif). C'est le pire cas
d'AES-GCM. C'est pourquoi on dérive un nonce per-chunk via
`base_nonce[:8] || pack("!I", chunk_index)` (ADR-0014). Avec un
base_nonce aléatoire 12 bytes par fichier + counter 32 bits, la
collision probability reste négligeable même au-delà de
2^32 chunks par fichier.

### Q5 — Pourquoi RSA 4096 et pas RSA 3072 ?

NIST SP 800-57 Part 1 Rev 5 confirme RSA-3072 ≈ 128 bits de
sécurité jusqu'au 2030+. Mais on a une marge : un RSA-4096 ≈
152 bits tient au-delà 2040. Coût performance : ~3× le temps
KeyGen mais ça arrive une seule fois par user à la création.
Pour wrap/unwrap d'une DEK 32 bytes, l'overhead est négligeable.

### Q6 — Pourquoi RSA-OAEP et pas RSA-PKCS#1 v1.5 ?

Bleichenbacher 1998 : padding oracle sur PKCS#1 v1.5 permet de
récupérer la clé en O(n²) requêtes. OAEP (PKCS#1 v2) ferme cet
oracle via un padding aléatoire. CDC mentionne RSA, on choisit
OAEP (RFC 8017 §7.1) avec MGF1-SHA-256.

### Q7 — Pourquoi hybride RSA+AES plutôt que RSA pur pour le partage ?

RSA-4096 chiffre au max 446 bytes (4096/8 - 42 padding OAEP).
On ne peut pas y mettre un fichier de 1 MiB. On wrap une DEK
AES-256 (32 bytes) avec RSA-OAEP, puis on chiffre le contenu
avec AES-GCM. C'est le pattern textbook _hybrid encryption_,
documenté ADR-0004.

## Anti-oracle (probable Q insistante)

### Q8 — Qu'est-ce qu'un oracle de déchiffrement ?

Un canal latéral qui révèle au-delà du fait que le déchiffrement
a échoué. Si le programme dit "tag invalide" vs "padding
invalide" vs "format inconnu", l'attaquant peut distinguer ces
modes et utiliser cette info pour reconstruire la clé / le
plaintext (Bleichenbacher, BEAST, POODLE...).

### Q9 — Comment vous l'avez mitigé ?

ADR-0015 : on collapse toutes les erreurs post-KDF
(DecryptionError, IntegrityError, CorruptedContainerError sur
truncation) vers le même `ANTI_ORACLE_MESSAGE`. Stderr et exit
code byte-identiques entre wrong-password et tampered-tag. Test
verrouillé : `tests/unit/test_cli_anti_oracle.py` lance des
subprocess réels (CliRunner ne capture que `typer.echo`, on a
découvert via audit qu'il était aveugle aux logs structlog).

### Q10 — Anti-oracle propagé jusqu'à la GUI ?

Oui. ADR-0016 §C : routers `/api/v1/decrypt` et `/api/v1/accept`
collapsent vers HTTP 422 + body constant. Le frontend
(`dashboard.decrypt.tsx`) traduit ce 422 vers une i18n string
`decrypt.anti_oracle_failure`. Le toast est byte-identique au
toast wrong-password.

## Architecture

### Q11 — Pourquoi Tauri et pas Electron ?

Tauri utilise WebView2 natif (Edge Chromium sur Windows, WebKit
sur macOS, WebKitGTK sur Linux), donc binary plus petit (15 MiB
vs 100+ pour Electron). Sandbox par défaut, allowlist Tauri
commands. Moins de RAM. Cf. ADR-0001.

### Q12 — Pourquoi un sidecar Python plutôt que tout en Rust ?

Le CDC impose Python pour la cryptographie. Migration tout-Rust
demanderait réécrire `cryptography`, `argon2-cffi`,
`SQLAlchemy`, `Alembic`. Time-to-CDC incompatible. Le coût IPC
loopback est négligeable (kernel-only). Trade-off accepté ADR- 0001.

### Q13 — Pourquoi loopback HTTP plutôt que stdin/stdout ?

Tauri a un plugin HTTP simple ; les Unix sockets / Named pipes
ont des chemins différents par OS (cross-platform pénible) ;
HTTP donne FastAPI gratuit. Le surcoût est ~1 ms par requête,
imperceptible pour des opérations crypto qui prennent 10-100 ms.

## Tests

### Q14 — Property-based testing, c'est quoi ?

Hypothesis génère des inputs aléatoires conformes à un schéma
(longueur, alphabet, contraintes). On écrit des invariants
(`decrypt(encrypt(x)) == x` pour tout `x`) et la lib trouve
les contre-exemples (shrink incluse). On a 4 fichiers
`tests/property/` qui couvrent 200+ examples par run :
crypto round-trip, KDF encode round-trip, container fuzz parse,
share-token round-trip.

### Q15 — Coverage 95 % — comment c'est mesuré ?

`pytest-cov` avec `--cov-branch` (branch coverage, pas juste
line). Per-package gate via `scripts/check_coverage_gates.py`
qui parse `coverage.xml` et applique des seuils différents par
sous-arbre (core ≥ 95 %, security ≥ 95 %, sidecar ≥ 90 %, autre
≥ 80 %). CI step bloquant.

## Sécurité

### Q16 — Quel est votre threat model ?

STRIDE par boundary, 6 adversaires modélisés (AD-1 à AD-6 dans
`docs/THREAT_MODEL.md` §3). En scope : remote network (AD-1, no
attack surface), local non-priv process (AD-2, principal), local
attacker with laptop (AD-3, BitLocker), curieux dev (AD-4),
malicious recipient (AD-5). Out-of-scope : cold-boot/DMA (AD-6,
mitigé OS).

### Q17 — Comment vous protégez contre la corruption mémoire ?

Best-effort : zero-fill de chaque `bytearray` détenant un secret
dans un `try/finally`. Mais Python's immutable `bytes` (renvoyé
par `kdf.derive`, par `cryptography`'s AESGCM ctx) ne peuvent
pas être zero-fill au niveau Python. Limite documentée
honnêtement dans `docs/THREAT_MODEL.md` §4.5. Future work :
mlock + ctypes pour les bufs sensibles.

### Q18 — Cold-boot attack ?

Out of scope. Mitigation OS-level (BitLocker / FileVault / dm-
crypt). Documenté résiduel R-2.

## Choix produit

### Q19 — Argon2id en opt-in, pas par défaut ?

Le CDC mandate PBKDF2 (formulation explicite). On respecte
formellement, et on offre Argon2id derrière `--kdf argon2id`.
Le `.crypt` header v1 encode le KDF id (1 byte) ; migration
fichier-par-fichier possible.

### Q20 — Limite 10 MiB pour share — pourquoi ?

`MAX_IN_MEMORY_MESSAGE_BYTES = 10 MiB`. Au-delà, refuser pour
ne pas swap-bomb un host avec peu de RAM. Streaming sharing est
roadmapé post-MVP — demande un changement format `.gbox-share`
v2 avec embedded streaming chunks. Le spec note honnêtement
cette limitation.

## Standards à citer

- NIST SP 800-38D (GCM)
- NIST SP 800-132 (PBKDF2)
- NIST SP 800-88r2 (sanitization)
- NIST SP 800-57 Part 1 Rev 5 (key sizes / lifetimes)
- OWASP Password Storage Cheat Sheet 2026
- OWASP ASVS V13 (API security)
- RFC 5116 (AEAD)
- RFC 8017 (PKCS #1 v2.2)
- RFC 9106 (Argon2)
- RFC 6455 (WebSocket)
- ANSSI Recommandations cryptographie
- CWE-208 (timing attack)
- CWE-307 (auth attempts)
