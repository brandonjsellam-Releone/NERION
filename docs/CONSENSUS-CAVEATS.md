<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion — Consensus Security Caveats (A40-CAVEATS)

**Purpose.** This document records, for external auditors and protocol
reviewers, the **honest limitations, open gaps, and known-acceptable caveats**
in Nerion's consensus and zero-knowledge layers. It is not a threat model (see
`docs/THREAT_MODEL.md`) and not an assurance matrix (see `docs/ASSURANCE.md`,
`docs/ASSURANCE-EXTENDED.md`). Its role is to make every caveat explicit and
findable in one place, so a reviewer is never surprised.

Every item below is honest: some are accepted design decisions, some are open
engineering gaps, and some are explicit audit obligations. Nothing here is
audited, FIPS-validated, or a non-infringement claim. Produced by the Nerion
R&D PhD Panel (Sprint 1, 2026-06-24).

---

## 1. Round-Skip Caveats (LEDGER-007)

### 1.1 Current state

A round-`r` block is required to carry only the `ViewChangeCert` for round
`r - 1`. The verifier checks that this single cert has ≥2/3 stake-weighted
signatures over `(height, prevHash, r-1)`. There is **no requirement to prove
that every intermediate round 0 … r-2 also timed out sequentially**.

Consequence: a ≥2/3 stake coalition can mint a single `ViewChangeCert` for an
arbitrarily high round and immediately propose at that round. This allows the
coalition to **cheaply re-roll the VRF leader draw** until a round whose
computed VRF leader is within the coalition. The current skip cost is **O(1)
in round distance**.

### 1.2 Safety impact

**None.** Finalizing a block always requires ≥2/3 attestations on the block
itself, independent of which round won. Accountable safety and equivocation
slashing (`ledger/src/equivocation.ts`) are bound to `(height, prevHash)`
and are round-agnostic. A colluding ≥2/3 can finalize any block regardless
of round-skip mitigation.

### 1.3 Liveness / fairness impact

The round-skip attack is exploitable **only by a ≥2/3 stake coalition** that
already controls liveness. A <1/3 adversary cannot forge any ViewChangeCert
and therefore cannot skip at all.

Within a ≥2/3 coalition, the attack reduces honest leader probability:
honest validators assigned to skipped rounds never get to propose. In the
worst case, a colluding supermajority can ensure that **only coalition members
ever become leader** at zero marginal cost.

### 1.4 Proposed fix and its caveats

**ADR-0019** specifies a chained `ViewChangeCert` structure where each cert
commits to the digest of the previous round's cert (`prevCertDigest`). Under
chaining, advancing `N` rounds requires `N` independently-quorum-signed certs,
making skip cost **O(N)**. The ADR is PROPOSED and UNIMPLEMENTED.

Known caveats of the chained design (from ADR-0019):

- **Cert availability.** The verifier needs the entire cert chain for a round-N
  block. A block carries one cert object; the full chain must be either
  embedded in the block (O(N) bytes) or gossiped / fetched from network
  state. If an intermediate cert is unavailable, the verifier must
  **fail-closed** (reject the block), which creates a potential liveness
  vulnerability if honest validators gossip unevenly. **This is the single
  largest unresolved question in ADR-0019.**
- **Still ≥2/3-gated.** The fix makes skipping expensive, not impossible.
  A coalition willing to pay O(N) quorum-signing work can still skip N rounds.
  The mitigation is economic/operational, not cryptographic.
- **Liveness under chaining.** The view-change timeout and fallback (ADR-0004)
  must be re-verified under the chained design to confirm that requiring a
  full cert chain does not extend recovery time after a network partition.
- **Digest canonicalization.** `certDigest` uses `encodeCanonical` + SHAKE256
  over the vote set projected to `(validator, suite, height, prevHash, round)`,
  excluding raw signature bytes for aggregator-independence. The canonical
  projection must be verified to be injection-free (no two distinct quorums
  can produce the same projected vote set).

**Auditors should treat LEDGER-007 as an open gap** until ADR-0019 is
implemented, the cert-availability design question is resolved, and an external
audit has reviewed the chained verifier. See `docs/SECURITY_FINDINGS.md` for
the authoritative finding disclosure.

---

## 2. Set-Binding Caveats (Threshold Receipts)

### 2.1 What set-binding means

In a k-of-n threshold receipt, **set-binding** is the property that the receipt
commits not just to the k-of-n threshold and the individual signatures, but
to the **exact named signer set** against which the threshold is evaluated.
Without set-binding, an adversary who controls a different signer set S' could
attempt to substitute S' for S post-issuance and claim the same receipt as
"authorized by S'".

Nerion's quorum receipt (ADR-0005, `receipts/src/quorum.ts`) binds to a named
signer set by taking signatures and checking membership against a fixed set
object passed to `verifyQuorum`. The set is identified by its members; the
verification is non-transferable across sets.

### 2.2 Current coverage

The property-based test (`receipts/test/quorum.property.test.ts`) includes a
set-substitution rejection case: a receipt finalized against set S must not
verify against a different set S'. This is the primary set-binding test.

### 2.3 Limitations

- **Sybil resistance is out of scope.** Nerion does not assert that the named
  signer set consists of independent parties. A single adversary controlling
  all k-of-n signing keys satisfies Nerion's quorum check. The protocol
  provides **authority proof** (k-of-n keys signed), not **independence proof**
  (k-of-n distinct principals decided independently).
- **Set identity is not cryptographically committed in the receipt body.** The
  receipt records the signer identities in the `signerIds` field, but there is
  no separate commitment (e.g. a Merkle root of the signer set) that could be
  verified against an external registry. Auditors relying on the signer-set
  field should verify against out-of-band key infrastructure.
- **Formal binding predicate not written.** The set-binding property is tested
  but not formally stated as a predicate in the ADR or ASSURANCE-EXTENDED.md.
  This is GAP-QR-2 in the extended assurance matrix. Recommendation: define
  `setBindingPredicate(receipt, S) = true iff every sig in receipt.sigs
  verifies under a key in S and |sigs ≥ k|` and state the security property
  formally in ADR-0005.

---

## 3. Zero-Knowledge Soundness Caveats

### 3.1 Soundness is classical only

The OR-proof underlying Nerion's ZK range proof and policy-satisfaction proof
(`disclosure/src/zkrange.ts`, `policyproof.ts`) is sound in the **classical
random-oracle model** only. The Fiat-Shamir transform applied to a Sigma
protocol is secure in the ROM, but its QROM security requires additional
analysis (see Unruh 2012, Don et al. 2020) and is **not yet established for
Nerion's specific construction**.

Implication: a quantum adversary capable of querying SHAKE256 in superposition
may be able to **forge a valid in-range proof** for an out-of-range amount.
This is a future risk, not a present threat (no quantum computers of this scale
exist). However, it means Nerion's ZK layer does **not** provide post-quantum
soundness guarantees.

**Amount confidentiality (hiding) is unaffected.** Pedersen commitment hiding
is information-theoretic / unconditional — no adversary, classical or quantum,
recovers the committed amount from the commitment or proof transcript.

### 3.2 n ≤ 251 bit-length cap

The soundness of the range proof `0 ≤ amount < threshold` depends on the bit
recomposition `Σ b_i·2^i` not wrapping modulo the ristretto255 group order
`L = 2^252 + d`. The protocol enforces `n ≤ 251`, which guarantees
`2^{n+1} ≤ L` and prevents aliasing.

This bound is verified to be tight: the +1 margin is required because both
`amount` and `diff = threshold-1-amount` are ranged simultaneously, and their
magnitudes push up toward `2^{n+1}`. A weaker cap of `n ≤ 252` introduced the
ZKRANGE-002 vulnerability (found and fixed 2026-06-21); `n ≤ 251` is the
correct safe bound.

**Audit obligation:** the `n ≤ 251` argument is a priority item for the
external ZK/crypto audit. One off-by-one has already slipped; the formal
off-by-one argument must be independently verified.

### 3.3 Per-bit vs. single-transcript challenge binding

The current `statementHash` binds all `2n` bit commitments and parameters into
every per-bit challenge. However, the generators `G` and `H` are **not**
currently hashed into the challenge transcript. If a code path ever
parameterized the generators, the transcript would be non-self-describing and
challenges could be reused across different generator sets.

ADR-0017 proposes a single-transcript tightening: one root challenge over all
first-messages and generators. This is audit-gated (not yet implemented).
Until it is implemented, the generator-binding gap is a **defense-in-depth
caveat**, not a known exploitable vulnerability for the current fixed-generator
construction.

---

## 4. ML-DSA-87 Usage Caveats

### 4.1 Classical security level

ML-DSA-87 (FIPS 204, formerly Dilithium5) provides ≥256-bit classical security
and ≥128-bit quantum security under MLWE + MSIS assumptions. It is the highest
security parameter set in FIPS 204 and is appropriate for long-term post-
quantum use under EU AI Act governance requirements and NIST AI RMF.

### 4.2 QROM tightness gap

MLWE and MSIS are known to be hard in the QROM (Kiltz, Lyubashevsky, Schaffner
2018; Peikert-Pepin 2021). However, the reduction from QROM-MLWE/MSIS to
ML-DSA-87 security has a **tightness gap**: the concrete quantum security
level derived from the reduction is somewhat lower than the classical 256-bit
parameter suggests. For Nerion's current usage (intent commitments, quorum
receipts), this gap has not been analyzed to determine the effective quantum
security margin.

**Residual obligation:** confirm that the effective quantum security under the
QROM reduction is still ≥128 bits for Nerion's specific key sizes and
deployment parameters.

### 4.3 Deterministic vs. hedged signing

FIPS 204 defines both deterministic (no per-signature randomness) and hedged
(additional randomness) ML-DSA-87 variants. Nerion must document which variant
is in use and confirm that the KAT vectors in `crypto/vectors/` correspond to
the variant actually implemented. A mismatch between variant documentation and
implementation would not be security-breaking (both variants are secure) but
would constitute an audit discrepancy.

### 4.4 Side-channel resistance

FIPS 204 / ML-DSA-87 is not assessed for side-channel resistance in Nerion's
implementation. The `@noble/curves` implementation does not claim constant-time
guarantees for all code paths. This is an **accepted limitation** for the
current Local/Private development maturity level, and is flagged for any
production deployment context.

---

## 5. Validator-Set and Protocol Composition Caveats

### 5.1 Quorum threshold must be ≥ 2f+1

For a BFT protocol tolerating f Byzantine validators in a committee of n=3f+1,
all safety-critical threshold checks must use **2f+1**, not f+1 or t+1 (where
t is a different threshold parameter). Using f+1 provides only crash-fault
tolerance, not Byzantine-fault tolerance.

Nerion's `verifyViewChangeCert` uses a BigInt cross-multiply against
`finalityNum/finalityDen` which should encode 2/3 stake. **Auditors must
verify** that the `finalityNum/finalityDen` parameters passed at all call sites
correctly implement ≥2f+1 (i.e. >2/3 stake), and that no caller can pass a
weakened threshold.

### 5.2 Classical ZK + PQ consensus interaction

The protocol combines:
- Classical ZK proofs (soundness breaks under quantum adversary)
- PQ signatures (ML-DSA-87, sound in QROM with tightness gap)
- PQ KEM (ML-KEM-1024 + P-384 hybrid)

These layers do **not** compose into a fully post-quantum protocol: the ZK
layer's soundness failure under a quantum adversary is not mitigated by the PQ
signature layer. A quantum adversary could forge an in-range ZK proof while
the ML-DSA-87 signatures remain sound. Nerion explicitly labels this gap in
`ASSURANCE.md` and `ASSURANCE-EXTENDED.md` (GAP-ZK-10).

### 5.3 Attestation-round binding

Round is deliberately excluded from `attestMessage` (LEDGER-EQUIV-001) to
preserve same-height equivocation comparability. This means attestations for
the same block at different rounds are cross-comparable for slashing, but it
also means the attestation itself cannot prove "this block was finalized at
round r." The round is recorded in the block header and the ViewChangeCert,
not in the attestation. Auditors should not expect the attestation to pin the
round.

---

## 6. What These Caveats Do Not Affect

The following properties are **not weakened** by any of the above caveats:

- **Amount confidentiality (hiding).** Pedersen commitment hiding is
  information-theoretic. No adversary, classical or quantum, recovers the
  committed amount from the proof transcript. Harvest-now-decrypt-later does
  not apply.
- **Receipt non-repudiation.** A finalized quorum receipt is bound to a
  specific `(height, prevHash, intent-digest)` by the ML-DSA-87 signatures of
  quorum members; forgery requires breaking ML-DSA-87.
- **Log tamper evidence.** Merkle tree consistency proofs are cryptographic;
  a tampered log produces a detectable inconsistency regardless of the
  round-skip or ZK soundness caveats.
- **Default-deny admission.** The kernel's `decide()` fail-closed property
  (C8) does not depend on ZK soundness; even if a ZK proof were forged, the
  forged proof is checked against the kernel's policy evaluator, which operates
  on the decoded permit token, not the raw proof bytes.

---

## 7. Audit Checklist for Reviewers

The following items are explicitly flagged for independent external audit:

| Item | Priority | Location |
|---|---|---|
| `n ≤ 251` off-by-one argument (ZKRANGE) | HIGH | `ADR-0017 §(d)`, `zkrange.ts` |
| Single-transcript FS tightening and generator binding | HIGH | `ADR-0017 §(c)` |
| `dlog_G(H)` NUMS argument in ROM | HIGH | `ADR-0016 §(a)` |
| OR-proof QROM soundness | HIGH | `ASSURANCE-EXTENDED.md` GAP-ZK-10 |
| Chained ViewChangeCert cert-availability design | HIGH | `ADR-0019` §5 Residual assumptions |
| ML-DSA-87 QROM tightness margin for Nerion parameters | MEDIUM | `ASSURANCE-EXTENDED.md` PQ-2 |
| Formal set-binding predicate in quorum receipts | MEDIUM | `ADR-0005`, `ASSURANCE-EXTENDED.md` GAP-QR-2 |
| Canonical vote-set digest injectivity | MEDIUM | `ADR-0019 §1 certDigest` |
| Quorum threshold is ≥ 2f+1 at all call sites | MEDIUM | `ledger/src/leader.ts` |
| `attestMessage` round-exclusion soundness under chaining | LOW | `ledger/src/equivocation.ts`, `ADR-0019` |

---

*This document is reviewed by the Nerion R&D PhD Panel and updated as caveats
are resolved. An unresolved caveat does not mean the system is broken — it
means the formal argument is incomplete or the gap is accepted and bounded. The
goal is zero unacknowledged caveats, not zero caveats.*

---

## 8. PhD Panel Sprint 1 — Precision addendum (2026-06-24)

This section records additional precision and corrective notes from the Mistral Large PhD-seat
review (Sprint 1, 2026-06-24). These notes tighten the language of existing caveats; they do not
add new findings.

### 8.1 Round-skip caveat: game-based definition

For auditors who need a game-based formalization of the LEDGER-007 attack:

```
Game RoundSkipAttack(Adv, n_validators, f_byzantine):
    Adv controls f_byzantine validators
    Honest validators follow the view-change protocol
    (view_number, finalized_log) <- Adv.run_consensus()
    if view_number > last_committed_view + 1
       AND finalized_log == last_committed_log:
        return 1  # Attack: round was skipped at no honest-measurable cost
    else:
        return 0
```

**Before ADR-0019:** Adv wins with O(1) work (one ViewChangeCert for the target round).

**After ADR-0019 (when implemented):** Adv wins only by producing N chained certs for N skipped
rounds. Each cert requires an independent >=2/3 quorum signature. Win probability for a <1/3
adversary: negligible. Win cost for a >=2/3 coalition: O(N) signing operations.

The critical constraint: this game only measures fairness cost, not safety. A >=2/3 coalition can
win this game even with the fix — it just becomes more expensive.

### 8.2 Set-binding caveat: precise computational assumption

"Set-binding" for Pedersen commitments requires care. A Pedersen commitment `C = v·G + r·H` is:

- **Perfectly hiding**: information-theoretic; an adversary learns nothing about v from C.
- **Computationally binding**: no PPT adversary can produce (v, r) and (v', r') with v != v' and
  `v·G + r·H = v'·G + r'·H`. This reduces to dlog hardness: if dlog_G(H) = t is known then
  `v' = v + t·(r - r')` is trivially computable. The binding assumption is: dlog_G(H) is unknown.

"Set-binding" in the quorum receipt context is a DIFFERENT property: the receipt commits not just
to values v but to the set S = {v_1, ..., v_k} of valid signers. This property is not provided
by Pedersen commitments alone. In Nerion's quorum receipt:

- The receipt is set-bound because each individual signature is verified against membership in the
  named set S (checked in `verifyQuorum`).
- The set S itself is identified by the signer identities in the receipt struct.
- The BINDING of the set S to the receipt is: the receipt is only valid when verified against
  the correct set S (a different set S' produces verification failures).
- The WEAKNESS is: the set S is not independently committed (e.g. via a Merkle root of a registry),
  so the set-binding guarantee depends on the verifier supplying the correct S. A verifier who
  supplies a wrong S will get a wrong answer, but the receipt itself does not prevent this.

Formal definition for auditors:

```
Set-Binding Predicate(receipt, S):
    return (
        forall sig in receipt.sigs:
            sig.signer in S AND verify(sig, receipt.signed_body) == true
        AND count(valid sigs) >= k
        AND count(valid sigs) <= |S|
    )
```

This predicate is the correct target for PROP testing and is what the current property test covers.
The gap is that the set S is externally supplied, not committed in the receipt.

### 8.3 ZK proof replay across views

A ZK range proof in Nerion is bound to a specific Pedersen commitment `C = v·G + r·H`. The proof
does NOT intrinsically bind to a consensus view number. This means a valid proof for commitment C
in view v_1 is also a valid proof for the same commitment C in view v_2. This is acceptable because
the commitment itself is re-evaluated per-receipt by the kernel (`decide()` creates a fresh
commitment per intent). However:

**Auditors must verify** that the receipt-issuance flow does not allow a prover to submit a proof
generated for a prior receipt in a new session without the kernel re-committing. Specifically:

- `commitbind.ts` embeds `commitment.toBytes()` into the public `boundIntentDigest` (ADR-0013),
  which is then signed by the quorum. If the quorum re-signs a receipt with the same commitment
  bytes from a prior session, the proof is technically reused but the receipt body is fresh.
- The honest scope: proof reuse across views is not currently an attack surface because proofs
  are not directly submitted by untrusted parties — they are generated by the protocol. If a future
  API exposes proof submission, the view binding must be added to the FS transcript.

### 8.4 BFT quorum threshold precision

For an n-validator committee with at most f Byzantine validators (f < n/3), the correct thresholds
for each purpose are:

| Property | Required threshold | Nerion's mechanism |
|---|---|---|
| Safety (no two conflicting finalizations) | >2/3n distinct valid votes | >=2/3 stake in `verifyViewChangeCert` and `verifyFinalized` |
| Liveness (at least one honest response) | >1/3n distinct valid votes (f+1) | Not separately checked; implied by >=2/3 |
| Equivocation detection (slash eligibility) | 2 conflicting valid attestations from same validator | `equivocation.ts` same-height check |

Using f+1 for safety would allow a Byzantine adversary controlling f validators to satisfy the
threshold alongside just one honest validator, potentially forging a cert that no honest majority
confirmed. Nerion's use of >2/3 stake is correct.

**Auditors must also verify:** the BigInt cross-multiply in `verifyViewChangeCert` correctly
implements `attestingStake * finalityDen > totalStake * finalityNum` (strict greater-than, not
greater-or-equal) to avoid accepting exactly 2/3 stake (which could be satisfied by a split
colluding group). The LEDGER-PRECISION-002 finding addressed BigInt overflow; strict vs. non-strict
threshold inequality is a separate check.

---

*PhD Panel Sprint 1 addendum added 2026-06-24. Routes to external ZK/crypto + consensus audit.*
