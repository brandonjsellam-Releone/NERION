<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion — Security Findings Index (Team Apex internal audit campaign)

A stable, auditor-facing index of every finding from the **Team Apex** multi-model internal code
audit (2026-06-21). The narrative analysis, adjudications, and panel dissents live in
[council/team-apex-zkrange-2026-06-21.md](council/team-apex-zkrange-2026-06-21.md); this file is the
one-page map.

> **Honest framing (read first).** Team Apex is an **internal** adversarial review by a panel of
> independent model lineages (DeepSeek · Grok · Hermes · Gemini · OpenAI · Claude Opus 4.8 as
> lead/adjudicator), each handed the *actual source* and asked to break it; every dissent was
> adjudicated by re-derivation, not majority vote (twice this overturned a confidently-wrong "all
> clear"). **This accelerates but does NOT replace** the external ROS / Trail of Bits / OSTIF audit
> (still Gate 2). "Found + fixed internally" ≠ "audited." Soundness of the ZK layer remains
> classical/UNAUDITED; see [ASSURANCE.md](ASSURANCE.md).

## Severity legend

- **Bug** — a concrete soundness/privacy/safety break (would mis-verify or leak), fixed before any
  external audit.
- **Hardening** — not exploitable as written, but closes a latent class (downgrade, domain
  separation, precision) an auditor would flag.
- **Validated** — adversarially reviewed, no change required.

## Findings

| ID | Component | Class | Sev | Status |
|---|---|---|---|---|
| ZKRANGE-002 | `disclosure/zkrange.ts` | range-proof n=252 wraparound (negative diff aliases into [0,2ⁿ) since L=2²⁵²+d) | **Bug** | Fixed — n≤251 both sides + regression test |
| CB-001 | `disclosure/commitbind.ts` | public binding digest hashed the plaintext amount → brute-forceable | **Bug (privacy)** | Fixed — amount omitted (bound by the hiding commitment + opening-checked verify) |
| RCPT-001 | `receipts/receipt.ts`, `disclosure/selective.ts` | logged v:1 receipt `commitments.intent` leaked the amount via brute-force | **Bug (privacy)** | Fixed — salted/hiding intent commitment, ADR-0014, conformance C23 |
| (PSP hardening) | `disclosure/policyproof.ts` | digest now binds explicit bounds; `proveBelow` n≤251 cap | Hardening | Fixed |
| KERNEL-TIME-001 | `capabilities/grant.ts` (kernel path) | non-finite `now` skipped the validity window | **Bug** | Fixed — `Number.isSafeInteger(now)` fail-closed |
| CAP-001 | `capabilities/capability.ts` | grant signature didn't bind `suite`; `grant.id` not re-derived | Hardening | Fixed — suite+domain-tag binding; id content-hash check |
| CAP-DELEG-001 | `capabilities/capability.ts` | `delegable:false` enforced only in `attenuate()`, not `verifyChain` | **Bug** | Fixed — `verifyChain` rejects onward delegation from a non-delegable parent |
| PERMIT-001 | `planes/permit.ts`, `crypto/envelope.ts` | symmetric permit key shared across audiences → cross-audience forgery | **Bug** | Fixed — per-(session,audience) HKDF keys, ADR-0015, conformance C22 |
| QUORUM (receipts) | `receipts/quorum.ts` | top-level domain separation on the signed body | Hardening | Fixed |
| ATTEST-FMT-001 | `attest/software.ts` | policy/TEE routing keyed off the UNSIGNED envelope format | **Bug** | Fixed — bind to the signed `claims.format` |
| ATTEST-TIME-001 | `attest/software.ts` | non-finite clock/`notAfter` skipped expiry | **Bug** | Fixed — fail-closed |
| ATTEST-NOFM-001 | `attest/software.ts` | n-of-m counted formats only → one attester satisfied the quorum | **Bug** | Fixed — distinct formats AND distinct attesters |
| ATTEST-SUITE-001 | `attest/software.ts` | evidence signature didn't bind `suite` | Hardening | Fixed — suite + domain tag in the signed message |
| ATTEST-NOFM-002 | `attest/software.ts` | `appraiseNofM(n≤0)` trivially passed / indexed an empty array | **Bug** | Fixed — `n≥1` fail-closed |
| LEDGER-001 | `ledger/equivocation.ts` | accountable-finality equivocation detection + slashing | (feature) | Implemented |
| LEDGER-002 | `ledger/sortition.ts` | proposer could grind `round` to self-elect | **Bug** | Fixed — canonical round |
| LEDGER-003/004 | `ledger/chain.ts` | suite pinning + no-throw on hostile suite in `verifyFinalized` | **Bug** | Fixed |
| LEDGER-005 | `ledger/chain.ts` | block height pinned to chain position | Hardening | Fixed |
| LEDGER-VRF-001 | `ledger/chain.ts` | negative `round` skipped the view-change cert (sub-⅓ grind) | **Bug** | Fixed — non-negative-integer round |
| LEDGER-EQUIV-001 | `ledger/equivocation.ts` | cross-height attestations forged a false "equivocation" (slash honest) | **Bug** | Fixed — same-height binding |
| VRF-001 | `ledger/vrf.ts` | non-prime-order / torsion key admitted multiple valid outputs | **Bug** | Fixed — non-identity + torsion-free check on Y and Γ |
| GOSSIP-CENSOR-001 | `ledger/chain.ts` | zero-stake gossiper could flood garbage attestations and censor finality | **Bug** | Fixed — ingress verifies the safety-counted signature |
| LEDGER-PRECISION-001 | `ledger/sortition.ts`, `chain.ts` | `attestingStake*finalityDen` overflowed 2⁵³, corrupting the 2/3 threshold | **Bug** | Fixed — BigInt finality + sortition + test |
| GOV-QUORUM-001 | `governance/quorum.ts` | approval not bound to its committee → cross-quorum consent transfer | **Bug** | Fixed — `quorumId` bound into every approval |
| GOV-TIME-001 | `governance/quorum.ts` | non-finite `now` skipped the proposal validity window | **Bug** | Fixed — `Number.isSafeInteger(now)` fail-closed + test |
| GOV-SUITE-001 | `governance/quorum.ts` | approval signature didn't bind `suite` (PS-1/PS-5 share ML-DSA-87) | Hardening | Fixed — suite in `proposalBytes` + test |
| GOV-QID-001 | `governance/quorum.ts` | `quorumId` truncated to 96-bit — but it's the consent-isolation binding | Hardening | Fixed — un-truncated |
| SETTLE-001 | `settlement/credits.ts` | signed CreditGrant replayable to double-credit | **Bug** | Fixed — (account,nonce) one-shot |
| SETTLE-002 | `settlement/credits.ts` | `verifyGrant` didn't bind a trusted issuer (anyone self-signs) | **Bug** | Fixed — trusted-issuer parameter |
| crypto foundation | `crypto/cbor.ts`, `envelope.ts`, `symmetric.ts` | canonical-CBOR injectivity, suite/domain binding, constant-time, CSPRNG | **Validated** | No change; AES-GCM caller-nonce warning added (AEAD has no prod caller) |
| `keystore/hbs-state.ts` | one-time-signature index management (SP 800-208) | reserve-before-sign, anti-rollback, software store hard-gated | **Validated** | No change |

## Deep-dive validations

- **`disclosure/zkrange.ts` — SOUND (exhaustive 3-lens pass, 2026-06-21).** Beyond the surface sweep
  that found ZKRANGE-002, the range proof got a structured deep-dive with each seat on a distinct
  surface: **DeepSeek** (Fiat-Shamir / "Frozen Heart" + challenge derivation), **Grok** (CDS OR-proof
  special-soundness + the `Σ Cᵢ·2ⁱ == target` bit-decomposition linkage), **Hermes** (dual-range
  mod-L aliasing + ristretto encoding/torsion hygiene). All three independently concluded **no
  forgery** under the discrete-log assumption + ROM, post-ZKRANGE-002. Confirmed: strong FS (all
  commitments bound before the challenge; per-bit domain separation), unbiased challenge reduction
  (~2⁻²⁶⁰), gap-free dual range at n≤251, and `cDiff` binding the *same* blinding `r` so the two
  ranges pin ONE committed amount. Hardening notes (not breaks): a `buildBits` sum-integrity unit
  test (currently covered transitively by `verifySub`'s `combined==target` check); ristretto's
  canonical decode already rejects non-canonical/torsion points. **Still classical-ROM + UNAUDITED —
  this internal pass informs, not replaces, the external ZK audit.**

## Known residuals (honest, not yet fixed)

- **Stake/credit arithmetic > 2⁵³** — `totalStake()` and credit balances sum in JS `Number`; the
  consensus-critical *finality comparison* is now BigInt (LEDGER-PRECISION-001), but a full
  bigint-stake migration to lift the 2⁵³ sum bound is tracked (docs/STATUS.md). Credits are not
  safety-critical and stay far below the bound.
- **Deterministic sortition leaks the leader** — `selectLeader` is publicly recomputable; private,
  grind-resistant sortition is the (implemented but not-yet-wired) ECVRF path (`ledger/vrf.ts`,
  ADR-0004).
- **v:2 amount-privacy-with-proofs** — the salted v:1 receipt (RCPT-001) makes the *log leaf* hiding;
  reveal-nothing-prove-a-predicate remains the v:2 PSP/Pedersen path (ADR-0006/0013).
- **Plane-1 permit replay window** — a captured PermitToken is replayable for its (short) validity
  window; single-use is the resource's idempotency duty (THREAT_MODEL M-P1-1).
- **The whole construction is UNAUDITED** and uses bespoke ZK in the classical ROM. No production
  claim until the external audit + FTO opinion.
</content>
