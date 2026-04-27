# Notes examen théorique 1h (J-06)

Fiche A4 recto-verso pour la préparation. Selon CDC : examen
individuel 1h en parallèle de la soutenance, théorie crypto +
mise en œuvre Python.

## I. Crypto fondamentaux

### Symmetric vs Asymetric

| Aspect     | Symmetric (AES)  | Asymmetric (RSA)         |
| ---------- | ---------------- | ------------------------ |
| Clé        | Une, partagée    | Paire (public/private)   |
| Vitesse    | ~5 GB/s (AES-NI) | ~200 op/s (RSA-4096)     |
| Use case   | Bulk encryption  | Key wrap, signature      |
| Clé taille | 256 bits suffit  | 4096 bits = 152 bits sec |

### AEAD

Authenticated Encryption with Associated Data. Bundle
confidentialité + intégrité en un appel. AES-GCM, ChaCha20-
Poly1305. Inputs : key, nonce, plaintext, AAD (associé).
Output : ciphertext + tag. Decrypt rejette en bloc si tag
invalide.

### KDF (Key Derivation Function)

Transforme un password (basse entropie) en clé crypto (haute).
Pourquoi : empêcher brute-force GPU sur des passwords humains.
Param : salt (random per-user), itérations (réglent le coût).

- **PBKDF2** : SHA-256 itéré N fois. Memory-cheap = vulnérable
  GPU farms.
- **bcrypt** : memory-cheap aussi, plafonné 72 chars.
- **Argon2id** : memory-hard. Param `m, t, p`. Recommandation
  OWASP 2026 par défaut.
- **scrypt** : ancêtre Argon2.

### HMAC

Hash-based Message Authentication Code. `HMAC(key, msg) =
H((key XOR opad) || H((key XOR ipad) || msg))`. Construction
qui résiste aux attaques length-extension de SHA-1/2. Comparer
toujours en temps constant via `hmac.compare_digest`.

### Block cipher modes

- **ECB** : ne pas utiliser. Patterns visibles.
- **CBC** : nécessite IV imprévisible. Pas d'auth → padding
  oracle (Vaudenay 2002).
- **CTR** : XOR avec keystream(counter). Fragile au nonce reuse.
- **GCM** : CTR + GHASH. AEAD natif. **Catastrophique** sur
  nonce reuse (recover GHASH key + XOR plaintexts).
- **GCM-SIV** : RFC 8452. Tolère nonce reuse.

## II. Cryptanalyse de base

### Bleichenbacher (1998)

Padding oracle sur RSA PKCS#1 v1.5. Le décrypteur révèle "padding
valide" vs "padding invalide". L'attaquant adapte le ciphertext
itérativement et reconstitue le plaintext en O(n²) requêtes.
Mitigation : RSA-OAEP (RFC 8017) qui ne fournit plus l'oracle.

### Padding oracle CBC

POODLE, BEAST. Le décryteur réagit différemment (timing, message)
selon la validité du padding PKCS#7. AES-GCM élimine le problème
(pas de padding, AEAD).

### Timing attack (CWE-208)

Comparaison naïve `==` sur strings retourne tôt sur premier
char différent → on observe le timing pour deviner char-by-char.
Mitigation : `hmac.compare_digest` (constant-time). Côté
hardware : AES-NI évite les table lookups exploitables par
cache attacks.

### Side-channels

- Cache (Flush+Reload, Prime+Probe).
- Power analysis (DPA).
- Acoustic / EM emanations.
- Speculative execution (Spectre, Meltdown).

Mitigations : constant-time impl, hardware AES-NI, separation
of address space.

### Brute-force vs rainbow table

- Brute-force : essayer toutes les combinaisons. KDF + salt
  augmente le coût par essai.
- Rainbow table : pré-calcul. Salt unique (random ≥ 128 bits)
  rend les tables inopérantes.

## III. Python crypto

### `cryptography` library

- High-level Fernet : token symétrique opaque, pas pour interop.
- Hazmat layer : AES-GCM, RSA-OAEP, KDFs, primitives.
- C-backend (OpenSSL) ou Rust-backend.

### `secrets` module

Utilise OS CSPRNG (`getrandom(2)` Linux, `BCryptGenRandom`
Windows). Méthodes : `secrets.token_bytes(n)`, `token_urlsafe(n)`,
`token_hex(n)`, `randbelow(upper)`. **Ne jamais** utiliser
`random.*` pour la crypto.

### `hmac.compare_digest`

```python
import hmac
hmac.compare_digest(a, b)  # constant time, retours bool
```

Refuse de comparer si types différents. Wrapper sur la primitive
`CRYPTO_memcmp` d'OpenSSL.

### Async (FastAPI + sqlalchemy[asyncio])

- `async def` corrige les I/O bound.
- `asyncio.to_thread()` pour code CPU-bound dans handler async.
- `aiosqlite` driver async pour SQLite.

### Type hints + mypy strict

- `mypy --strict` rejette `Any`, missing return types, untyped
  defs.
- `from __future__ import annotations` pour postponed eval (PEP
  563).
- `TypedDict`, `Protocol` pour les structures.

### pytest fixtures

```python
import pytest
@pytest.fixture
def tmp_vault(tmp_path):
    yield tmp_path / "vault.db"
```

`tmp_path` (pathlib.Path), `tmp_path_factory`, `monkeypatch`,
`capsys`, `caplog`. `pytest.parametrize` pour les data-driven.

### Hypothesis

```python
from hypothesis import given, strategies as st

@given(st.binary(min_size=0, max_size=10_000),
       st.text(min_size=12))
def test_roundtrip(plaintext, password):
    ct = encrypt(plaintext, password)
    assert decrypt(ct, password) == plaintext
```

Auto-shrink sur les contre-exemples.

## IV. Standards à connaître

- **NIST SP 800-38D** — GCM mode of operation. §6.1 : nonce
  uniqueness. §8.3 : AAD usage.
- **NIST SP 800-132** — PBKDF2. §5.3 : ≥ 1000 itérations
  (mais OWASP demande 600k aujourd'hui).
- **NIST SP 800-88r2** — Sanitization. Distingue clear / purge /
  destroy. §5.2 : SSD wear-levelling rend overwrite best-effort.
- **NIST SP 800-57 Part 1 Rev 5** — Key management. RSA-3072
  ≈ 128 bits sec.
- **OWASP Password Storage Cheat Sheet 2026** — PBKDF2 600k,
  Argon2id m=64MiB t=3 p=1.
- **OWASP ASVS V13** — API security verifications.
- **RFC 5116** — AEAD interface.
- **RFC 8017** — PKCS #1 v2.2 (RSA-OAEP).
- **RFC 9106** — Argon2.
- **CWE-208** — Observable timing discrepancy.
- **CWE-307** — Improper restriction of excessive auth attempts.
- **ANSSI** — Recommandations cryptographie (FR).

## V. Pitfalls fréquents

- Timing attack sur compare → `hmac.compare_digest`.
- Nonce GCM reuse → catastrophique (toujours dériver per-chunk).
- KDF iterations trop basses → brute-force GPU.
- Salt prédictible → rainbow table.
- `random.random()` pour crypto → not CSPRNG.
- Bare `except:` → swallow security errors.
- Mock dans tests d'intégration → désync avec réalité.
- Logging des secrets → CWE-532 (information exposure through
  log files).
