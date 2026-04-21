# 003 — Share an encrypted file with another local user (RSA-OAEP)

- Status: draft (skeleton)
- Tracks: F-11 from `docs/SPEC.md`
- Depends on: spec 001 (encrypt) and spec 002 (decrypt).

## Behaviour

A _sender_ user produces a `.gbox-share` token bundling:

1. The recipient's user identifier.
2. The original `.crypt` file (or a reference to it on shared storage).
3. The data-encryption key (DEK) wrapped under the recipient's RSA-OAEP-SHA256
   public key.
4. A signature over (1, 2, 3) by the sender's RSA-PSS private key.

The recipient imports the `.gbox-share`, the system verifies the signature,
unwraps the DEK with the recipient's private key, and decrypts the bundled
`.crypt` to a local destination.

## Acceptance criteria (Gherkin)

```gherkin
Scenario: Round-trip share between two users on the same machine
  Given two locally registered users Alice and Bob
  And Alice has encrypted "secret.txt" → "secret.txt.crypt"
  When Alice runs "guardiabox share secret.txt.crypt --to bob -o share.gbox-share"
  And Bob runs "guardiabox accept share.gbox-share"
  Then Bob obtains "secret.txt" with bytes equal to Alice's original

Scenario: Tampered share token is rejected
  Given a valid share token whose signature byte has been flipped
  When Bob attempts to accept it
  Then the operation fails with IntegrityError
  And no plaintext is written

Scenario: Share to unknown recipient fails closed
  When Alice tries to share with a username that does not exist locally
  Then the operation fails with a clear "unknown recipient" error
  And no .gbox-share file is created
```

## Threat model deltas

- Adversary AD-5 (malicious recipient) **can** read the file — that is the
  intent. They cannot replay the share to a third party because the wrapped
  DEK is only decryptable with their own private key.
- Audit log entries are appended on both `share` and `share_accept` events.

## Plan / tasks

To be drafted before implementation begins.
