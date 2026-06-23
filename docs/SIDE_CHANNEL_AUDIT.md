<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Side-channel / timing audit — equality-comparison surface (R6)

> Source-level audit of every value-equality comparison in Nerion's production verification and
> admission paths. Scope: the **equality surface** (where a non-constant-time compare could become a
> byte-by-byte forgery/secret oracle). It is **not** a measured microarchitectural timing analysis —
> see the residual at the end. UNAUDITED reference implementation.

## Method

Enumerated (1) every `constantTimeEqual` call and (2) every `===` / `!==` / `.every(` / `.equals(`
byte-or-value comparison across `*/src` (excluding tests). Each comparison was classified by whether
either operand is **secret** (a key, MAC tag, shared secret, or sealing seed — where a timing oracle
lets an attacker recover/forge it) or **public** (a hash, public key, identifier, nonce challenge,
suite label, or protocol parameter — where the values are known to the attacker anyway, so compare
timing reveals nothing secret).

## Findings

### Secret-dependent comparisons — ALL constant-time ✔

| Site | Compares | 
|---|---|
| `crypto/src/symmetric.ts` (`HMAC_SHA384.verify`) | recomputed HMAC-SHA-384 tag vs supplied tag (PermitToken auth) — `constantTimeEqual` |
| `planes/src/node.ts` | session key vs expected — `constantTimeEqual` |
| `disclosure/src/commitbind.ts` | commitment / bound-intent digest equality — `constantTimeEqual` |
| `keystore/src/sealing-provider.ts` | unsealed-seed round-trip + sealed/trusted public-key checks — `constantTimeEqual` |
| `crypto/src/cose.ts`, `attest/src/software.ts` | COSE protected header / attester public key — `constantTimeEqual` (public, but constant-time regardless) |

`AES-256-GCM` tag verification and all signature verification (`ML-DSA-87`, ECDH P-384, X25519) are
delegated to the audited `@noble/*` libraries, whose constant-time properties are upstream.

### Public-value comparisons — fast `===` is correct ✔

Timing-safety is irrelevant when both operands are public. These use ordinary equality and **should**:
consensus hashes (`block/prev/leader/proposer/blockHash`, `ledger/src/chain.ts`,
`equivocation.ts`, `leader.ts`), validator public keys + ids (`sortition.ts`, `capabilities/src`),
the committed-suite label (`receipts/src/quorum.ts`), the **attestation nonce** (a public freshness
challenge, `attest/src/software.ts`), Merkle indices/hashes + the STH operator key (`translog/src`),
the ZK range parameter `n` (`disclosure/src/zkrange.ts`, `policyproof.ts`), and the disclosure
commitment-hash-vs-recompute (`disclosure/src/selective.ts` — the salt/value are already revealed to
the verifier on this path).

## Verdict

**No secret-dependent, non-constant-time equality exists in any production verification oracle.** The
one non-constant-time secret-ish compare in the tree is a *conformance self-check*
(`conformance/src/suite.ts` compares two locally-derived KEM shared secrets via hex `===`) — it is not
reachable by an attacker (it checks the suite's own encap/decap round-trip), noted only for tidiness.

## Residual (the genuine R6 — out of source-audit scope)

Deeper **microarchitectural / data-dependent-branch** timing in the primitives and the V8/platform
runtime, measured **under load**, is not addressable by reading source — it needs a timing-measurement
lab (and is largely a property of `@noble` + the engine, not Nerion's protocol code). This remains the
external-audit / measurement item. The equality surface above is the part that source review can
settle, and it is settled.
