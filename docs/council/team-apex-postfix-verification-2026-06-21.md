<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Team Apex — post-fix verification round (2026-06-21)

After the three audit fixes landed — **PERMIT-001** (per-(session,audience) HKDF permit keys, ADR-0015),
**TLOG-001/002** (consistency m=0 empty-root check + 32-bit-safe size bound), and **RCPT-001** (salted/hiding
v:1 intent commitment, ADR-0014) — a fresh panel re-reviewed the *implemented* code. The goal was a
"find-a-concrete-break" pass over the **fixes themselves**, since a fix is itself unaudited code.

**Panel (independent model lineages):** DeepSeek · Grok · Hermes · OpenAI · Claude Opus 4.8 (lead /
adjudicator). Each received the actual source of all three surfaces and was asked to forge a permit for a
different audience, forge a Merkle inclusion/consistency proof (or get a bogus size-0 STH accepted), or
recover the salted amount from the public log leaf.

## Result: the two crypto-binding fixes cleared unanimously; the log fix drew three FALSE POSITIVES

| Surface | Panel verdict | Adjudication |
|---|---|---|
| **PERMIT-001** per-audience HKDF keys | No break (4/4) | **SAFE.** The MAC is keyed by `HKDF(sessionKey, info=dCBOR[ctx, audience])`; a resource holding only its own derived key cannot re-key for a sibling audience without the raw session secret or an HKDF/HMAC break. `info` is canonical-CBOR (length-prefixed) so audiences cannot collide by string concatenation. |
| **RCPT-001** salted intent commitment | No break (4/4) | **SAFE.** The 32-byte CSPRNG salt is in the `Receipt` wrapper only, never in `receiptLeaf = dCBOR(body)`; without it the low-entropy amount is not brute-forceable from the public leaf. dCBOR `{d,salt,value}` is unambiguous. |
| **TLOG** Merkle consistency/inclusion | **Three findings — all FALSE POSITIVES** | See below. |

## The three TLOG findings, and why each is refuted

The panel **split with confidence in three different directions** — and all three were wrong. This is the
*inverse* of ZKRANGE-002 (where the minority report was right): here the lead had to refute confident
findings, not rescue a dismissed one. The discipline is identical — **re-derive the arithmetic and check it
empirically; never rubber-stamp the panel in either direction.**

1. **Grok + Hermes — "`m=0` accepts an arbitrary `root2`, so any size-n STH is declared consistent with the
   empty tree."** *Refuted.* The empty tree **is** a prefix of every tree, so the consistency *relation* is
   vacuously true for any `root2`; `root2`'s authenticity is carried by its **STH signature**, not by the
   consistency check. The TLOG-001 fix already constrains the *old* side (`root1 == emptyRoot`), rejecting a
   malformed/bogus size-0 STH. Accepting any genuine `root2` from genesis is correct RFC 6962 semantics.

2. **DeepSeek — "power-of-2 `m` rejects all valid consistency proofs (false negative), e.g. m=2, n=3."**
   *Refuted.* The claim conflates `chainInner` with `chainInnerRight`. In the power-of-2 branch `mask = 0`, so
   `chainInnerRight` (which acts only on set mask bits) is a no-op for `hash1` — correct — **but `chainInner`
   takes the `((index>>i)&1)===0 ? node(acc, proof[i]) : …` branch for every inner node when `mask=0`, so it
   DOES consume the inner proof and `hash2` reaches `root2`.** The case verifies. (The base suite's
   "consistency for all m≤n across sizes 1..16" already exercises m=2,4,8 and passes.)

3. (No third distinct true finding — OpenAI returned empty; the above two are the only substantive claims.)

## Evidence — exhaustive empirical cross-check (403 assertions, 0 failures)

To make the refutation airtight rather than argued, every inclusion and consistency relation was recomputed
against the built code for all tree sizes 1..12 and all `(m, n)`:

- power-of-2 `m` (2, 4, 8) consistency proofs **verify** → DeepSeek refuted;
- `m=0` accepts any genuine `root2` **but requires `root1 == emptyRoot`** → Grok/Hermes refuted, TLOG-001 intact;
- a forged `root1` **or** forged `root2` is **rejected** for `m>0` → soundness holds.

Baked into the gate as `translog/test/merkle-soundness.test.ts` (binds `root2` for `0<m<n`; documents the
`m=0` universal-prefix semantics) so the adjudication cannot silently regress.

## Extended coverage — ledger VRF (ECVRF-EDWARDS25519-SHA512-TAI) — **VRF-001 found + fixed**

The same panel (DeepSeek · Grok · Hermes · Gemini · lead) then audited `ledger/vrf.ts` (RFC 9381 ECVRF, the
grind-resistant leader-sortition primitive, ADR-0004) and `ledger/sortition.ts`. The VRF is **deliberately
classical** (edwards25519 DL) — a break is a liveness/fairness issue, not a safety one (finality is ML-DSA-87);
that PQ caveat is documented and out of scope.

**Adjudicated FALSE / known (the panel over-reached on three points):**
- *"Nonce deviates from RFC 9381."* **False** — the code is RFC 9381 **§5.4.2.2** (RFC 8032 nonce:
  `k = SHA-512(upper_half(SHA-512(seed)) ‖ H) mod L`), which Gemini confirmed and the **passing RFC 9381
  test-vector suite proves empirically** (a wrong nonce fails the KATs). DeepSeek/Grok cited the wrong variant.
- *"16-byte challenge is too short."* **False** — `cLen = 16` is correct for the ed25519 ciphersuite (Gemini).
- *"Sortition is grindable via `prevHash`."* **Known/documented** — `sortition.ts` is a deterministic
  selection; the private VRF that fixes content-grinding is the roadmapped ADR-0004 path (STATUS.md). Hermes
  also correctly noted the VRF is not yet wired into the active sortition.

**VRF-001 (real, fixed) — `verify()` omitted `ECVRF_validate_key`.** Convergent across DeepSeek/Grok/Hermes:
`verify` decoded the public key (and `Gamma`) but never checked it was a **non-identity, prime-order** point.
edwards25519 is a cofactor-8 group, and small-order / torsion-carrying points have *canonical* encodings that
`@noble` decode accepts. RFC 9381 §5.4.5/§7.4 requires key validation for **full uniqueness**; without it a
**malicious validator** could register a crafted key admitting multiple valid outputs per input and **grind
leader sortition**. (The panel's stronger *forgery* claims are over-stated — the 128-bit Fiat-Shamir challenge
blocks forgery regardless; the genuine gap is **uniqueness**, exploitable by an admitted-but-malicious validator.)

**Fix:** `verify()` now rejects any public key or `Gamma` that is the identity or not torsion-free
(`!pt.is0() && pt.isTorsionFree()`) — RFC 9381 §5.4.5 strengthened to full torsion-freeness. Legitimate keys
(`x·B`) and `Gamma = x·H` (with `H` cofactor-cleared) are torsion-free, so the RFC 9381 vector tests and all
existing VRF/chain tests still pass. Regression test `ledger/test/vrf-validate-key.test.ts` (rejects a
torsion-mangled key and a pure small-order key; legit prove→verify still returns β).

## Extended coverage — keystore HBS one-time-state (SP 800-208) — CLEARED

`keystore/hbs-state.ts` (reserve-before-sign for LMS/XMSS code signing; the no-OTS-index-reuse invariant,
conformance C18) was reviewed by DeepSeek · Grok · Hermes. **No logic defect.** `assertSingleTree` precedes
the sole mutation site, `reserve` is strictly monotonic + exhaustion-checked, a failed sign deliberately
wastes (never retries) a burned leaf, and height is validated on create + every reserve. The software store's
durability/rollback/clone gaps are documented and hardware-bound (gated behind `allowUnsafeSoftwareState`).

- *Adjudicated FALSE — DeepSeek "mutable state leak via public `state()`":* an artifact of the abbreviated
  review brief (which dropped the modifier) — the method is `private state(...)`. (TS `private` is
  compile-time; a caller already executing in the signer can manipulate any internal — not a meaningful
  bypass, and production uses a hardware counter.) DeepSeek's "reset `next` on sign failure" suggestion was
  also rejected: it would **reintroduce** reuse risk, contradicting the deliberate burn-a-wasted-leaf design.

## Extended coverage — keystore seed-custody / sealing providers — **CUSTODY-SEAL-001 found + fixed**

`keystore/sealing-provider.ts` (model B: a cloud KMS/HSM wraps a small PQC keygen *seed*; the at-rest
`SealedKey` blob is "safe to persist/replicate"). Reviewed by DeepSeek · Grok · Hermes — **unanimous CONFIRM**.

**CUSTODY-SEAL-001 (real, fixed) — the `SealedKey` blob is unauthenticated; `load()`'s integrity check is
self-referential.** `load()` unwraps the seed, re-derives the public key, and compares it to the blob's *own*
`publicKey` field — but both fields come from the (attacker-controllable) blob. With a **public-key wrap**
(Azure Key Vault **RSA-OAEP-256**, confirmed in `azure-kv.test.ts`), anyone who knows the *public* KEK can
craft a valid `wrappedSeed` for a chosen seed **offline** (no Azure permission), set `publicKey` to match, and
overwrite a replicated blob — **substituting a chosen signing key under any id**. The node then signs
receipts/permits/attestations with the attacker's key. The docstring's "a swapped blob fails loudly" was an
**over-claim**: it catches *corruption* (inconsistent blob), not a *consistent substitution*.

- **Backend-specific:** the **AWS** path uses a **symmetric** KMS key (`kms:Encrypt`, authenticated AEAD,
  requires the Encrypt grant) — a `wrappedSeed` is **not** forgeable offline, so AWS is not exposed to this
  variant. Confirmed by all three seats.
- **Scope/novelty:** undocumented — THREAT_MODEL covers only at-rest *confidentiality* (A11/HNDL), not blob
  *integrity/authenticity*. Severity High for Azure-RSA deployments with a replicated/untrusted blob store.
- **Fix:** `load(sealed, { trustedPublicKey })` now checks the re-derived key against an **out-of-band-trusted**
  public key (e.g. the value `provision()` returned, kept in an integrity-protected record), breaking the
  self-reference; a substituted blob is rejected. The corruption self-check is retained as defense-in-depth,
  and the docstring is corrected to state the integrity-vs-authenticity boundary plainly. Regression test
  `keystore/test/custody-seal.test.ts` *demonstrates* the vector (forged blob accepted without a trusted key)
  and *proves* the fix (rejected with it). Full architectural hardening (authenticated/symmetric wrap, or a
  node-held MAC / KV-`sign` over the blob, or an integrity-protected `(id→publicKey)` registry) is the
  recommended production follow-up.

## Extended coverage — settlement metering credits (P4) — **SETTLE-001 + SETTLE-002 found + fixed**

`settlement/credits.ts` (non-transferable, issuer-signed metering credits; P4/experimental). Reviewed by
DeepSeek · Grok · Hermes — **unanimous on two findings**:

- **SETTLE-001 (replay, HIGH) — `grant()` tracked no consumed nonce.** The grant signs a `nonce` but the
  ledger never recorded prior `(account, nonce)` pairs, so the same signed `CreditGrant` could be granted
  repeatedly to **double-credit**. **Fix:** a `consumedNonces` set (JSON-keyed `[account, nonce]`, no
  separator aliasing) rejects reuse before crediting.
- **SETTLE-002 (issuer trust, HIGH) — `verifyGrant` had no trusted-issuer binding.** It verified the signature
  under the grant's *self-declared* `g.issuer` key, so anyone could self-sign a grant under their own key and
  pass `verifyGrant`. Same footgun class as `verifyReceiptInclusion`'s `trustedIssuerKey`. **Fix:**
  `verifyGrant(g, trustedIssuer?)` rejects a grant whose issuer ≠ the supplied trusted key; the docstring
  states plainly that the unbound form is a signature self-check only.
- *Adjudicated NOT-a-defect — `tierCost` out-of-range:* the `?? 20` default maps any out-of-range/negative tier
  to the **maximum** cost — it fails toward over-charging (conservative), not under-charging, so it is safe by
  design (sided with Hermes; DeepSeek/Grok flagged it MEDIUM). `meter` over-spend and integer overflow were
  refuted (balance guard present; JS-number range adequate for P4, BigInt is the documented production path).

Regression test `settlement/test/credits-hardening.test.ts` (replay rejected / credited once; distinct nonces
independent; `verifyGrant` binds the trusted issuer and rejects an attacker self-signed grant).

## Extended coverage — remote attestation appraisal — **ATTEST-TIME-001 + ATTEST-NOFM-001 found + fixed**

`attest/software.ts` (RATS-style evidence appraisal). Reviewed by DeepSeek · Grok · Hermes — **unanimous on
the time bug**:

- **ATTEST-TIME-001 (expiry fail-open, HIGH) — the exact KERNEL-TIME-001 class.** `appraise()` checked
  `policy.now > claims.notAfter` with **no finiteness guard**; a `NaN` `policy.now` (the verifier's own clock)
  makes the comparison false and **silently skips the expiry check**, accepting a stale/expired attestation
  (and a non-finite signed `notAfter` never expires). **Fix:** fail closed unless `Number.isSafeInteger(now)`
  and `Number.isFinite(notAfter)` — mirrors the fixed `Number.isSafeInteger(ctx.now)` guard in capabilities.
- **ATTEST-NOFM-001 (heterogeneity, MEDIUM) — `appraiseNofM` counted distinct FORMATS only.** A single trusted
  attester could satisfy an N-of-M quorum across relabeled formats (the per-evidence checks pass; only format
  cardinality was counted). **Fix:** require `n` distinct formats **AND** `n` distinct attester keys
  (independent roots of trust). (Not trivially exploitable today — non-`software-dev` formats need a real quote
  verifier — but it strengthens the independence the quorum implies; sided with the panel on hardening.)
- *Adjudicated REFUTED — DeepSeek "verify measurements for non-hardware formats":* `software-dev` binds a
  session identity + nonce, not enclave measurements (those are the TEE verifier's job); not applicable.

Regression test `attest/test/attest-hardening.test.ts` (NaN/Infinity clock and non-finite `notAfter` rejected;
expired still rejected; 2 formats from one attester fail 2-of-M, 2 formats from two attesters pass).

## Net

The previously-landed fixes (PERMIT-001, TLOG-001/002, RCPT-001) plus the keystore-OTS state are **sound as
landed** — independently confirmed, with three TLOG false positives refuted by a 403-case empirical
cross-check. Extending coverage across the un-swept surface surfaced **six genuine fixes**: **VRF-001**
(`ledger/vrf.ts` missing `ECVRF_validate_key`), **CUSTODY-SEAL-001** (`keystore/sealing-provider.ts`
unauthenticated sealed blob under a public-key wrap), **SETTLE-001 + SETTLE-002** (`settlement/credits.ts`
grant replay + missing issuer binding), and **ATTEST-TIME-001 + ATTEST-NOFM-001** (`attest/software.ts` expiry
fail-open + N-of-M counting formats not attesters). Net code changes: `ledger/vrf.ts`,
`keystore/sealing-provider.ts`, `settlement/credits.ts`, `attest/software.ts`, plus six regression tests
(`translog/merkle-soundness`, `ledger/vrf-validate-key`, `keystore/custody-seal`, `settlement/credits-hardening`,
`attest/attest-hardening`). **Lesson recorded:** a multi-model panel produces confident *false positives*
(8 this campaign: 3 TLOG, 2 VRF, 1 keystore-OTS, 1 settlement-tierCost, 1 attest-measurements) as readily as it
confirms true findings — the adjudicator must re-derive and empirically verify **every** claim, in both
directions. Gate green at 365 tests; `npm run conformance` → 23/23.
