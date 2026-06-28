# PQC-4 — key-committing seal (close the AES-256-GCM non-commitment gap)

> Status: research-engineering. UNAUDITED, pre-FTO. Additive `SealedMessage` field + an open-side
> check; the AEAD key derivation is **byte-identical** (conformance 23/23 unchanged). No `Ps1` /
> `ps-*.json` change. Branch-only.

## What

`sealToKem` (ADR-0028) derives an AES-256-GCM key from the hybrid-KEM shared secret via HKDF-SHA-384
with rich context binding. But **AES-256-GCM is not key-committing**: a _partitioning oracle_ can craft
a single ciphertext that AEAD-verifies under two different derived keys (Len–Grubbs–Ristenpart). The
GCM tag alone cannot bind a ciphertext to _one_ key.

PQC-4 adds a **key-commitment**:

- `sealToKem` derives a 32-byte `keyCommitment = HKDF-SHA-384(ikm = derivedAeadKey, salt =
fixedDomainSalt, info = commitInfo)` — committing to the **derived AEAD key** (the canonical
  key-committing construction, per council: bind the exact key GCM uses, not merely the upstream
  secret), over the bound context, domain-separated by a distinct `'key-commitment'` discriminator
  and a fixed RFC-5869 salt. It is a one-way PRF output (reveals nothing about the key) and ships in
  the `SealedMessage`.
- `openSealed` re-derives the commitment from the re-derived AEAD key and **constant-time compares**
  it (`constantTimeEqual`) **before** the AEAD open. A mismatch — a partitioning-oracle second key, a
  wrong key (ML-KEM implicit rejection → different secret → different key → different commitment), or a
  grafted commitment — fails closed.

HKDF-SHA-384's 256-bit output gives ~2^128 collision resistance, so no second key/context yields the
same commitment, and a `SealedMessage` binds to **exactly one** (key, context).

## Tests

`crypto/test/seal-key-commitment.property.test.ts` (both hybrid KEMs): a valid seal carries a 32-byte
commitment and round-trips; a tampered commitment fails closed with the commitment error (checked
before the AEAD); a commitment **grafted from a different seal** is rejected (the message's own derived
key re-derives its own commitment, not the grafted one — the partitioning defense); a different
recipient cannot open. The 16 existing ADR-0028 seal tests stay green (backward-compatible).

## Why it is beyond the prior bar

ADR-0028 hardened the KDF _info_ binding but added **no** key commitment; AES-256-GCM is provably not
key-committing, so one ciphertext could validly open under two derived keys (partitioning-oracle /
multi-recipient confusion). Shipping a committing seal closes a documented current-SOTA robustness gap
that audited primitives alone do not address. The seal path is genuinely pre-load-bearing (its only
callers are its own tests), so this hardens it before it carries traffic.

## Scope / honesty

- Additive optional-in-spirit field + open-side check; the AEAD key derivation is unchanged
  (conformance 23/23, full gate green). Never touches SuiteID `Ps1` or `ps-*.json`.
- Commitment overhead is one extra HKDF expand per seal/open + one constant-time compare (microseconds).
- The robustness benefit is framed as **engineering** (closes the partitioning-oracle class), **not**
  an audited proof or a "committing-AEAD security theorem". `@noble` primitives remain UNAUDITED here.

_Origin: Beyond-Apex Frontier item PQC-4 (see [BEYOND_APEX_FRONTIER.md](./BEYOND_APEX_FRONTIER.md))._
