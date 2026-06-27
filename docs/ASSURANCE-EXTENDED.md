<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion — Extended Assurance Matrix (A39-EXTENDED)

**Status: PROPOSED — design-only additions. Not a security result. Not audited.**
Date: 2026-06-24. Produced by PhD Panel Sprint 1 (Track-B). Extends `docs/ASSURANCE.md` with a
guarantee × artifact × verification-method matrix covering the claims an external auditor (OSTIF,
OTF Security Lab / Radically Open Security, or a cryptography dissertation committee) would look for
beyond the P0–P4 claims in the base matrix. Nothing here overrides the base matrix.

The words "audited", "FIPS", "certified", and "non-infringement" do NOT apply to anything in Nerion
unless explicitly and externally established.

---

## How to read this matrix

Each row names a **guarantee** (the property), its **mechanism** (the artifact that delivers it), its
**substantiation** (how you verify the property today), and its **verification method and honest scope**
(what level of evidence the substantiation represents, and what it does NOT prove).

**Verification method codes:**
- `KAT` — pinned known-answer test vector; cross-implementation reproducible.
- `PROP` — randomized property test (fast-check); invariant survived a generated input space.
- `CONF(Cn)` — Nerion in-repo conformance check Cn; passes `npm run conformance`.
- `FUZZ` — fuzzing / mutation; no panic / no silent wrong answer over hostile inputs.
- `LOGIC` — internal design/logic argument in an ADR; not externally verified.
- `EXT-AUDIT` — external independent review (none completed; pending OSTIF / OTF).
- `FORMAL` — NIST-standardized algorithm or machine-checked proof.

Planned items are annotated **(planned)** — the control does not exist yet.

---

## Layer 1: Cryptographic Primitives

| Guarantee | Mechanism | Substantiation | Verification method | Honest scope |
|---|---|---|---|---|
| **ML-DSA-87 signature correctness** — verify iff signed by matching key under FIPS 204. | `crypto/src/mldsa.ts`; `@noble/post-quantum`. | KAT in `crypto/vectors/`; reproduced by `crypto/test/kat.test.ts`. | KAT · FORMAL (FIPS 204 algorithm) | Algorithm-compatible, NOT FIPS-validated; side-channel unassessed; `@noble` unaudited software. |
| **ML-DSA-87 secret-key representation safety** — canonical FIPS 204 encoding; wrong representation caught. | ADR-0024; key serialization tests. | KAT for secret-key-to-public round-trip; negative tests (ADR-0024). | KAT · TEST | Representation correctness only; key-compromise and side-channel not covered. |
| **ML-KEM-1024 encap/decap correctness** | `crypto/src/mlkem.ts`; FIPS 203. | KAT vectors. | KAT · FORMAL (FIPS 203) | Hybrid KEM retains classical P-384 leg (quantum-vulnerable, CBOM-flagged). |
| **SLH-DSA-SHAKE-256f correctness** | `crypto/src/slhdsa.ts`; FIPS 205. | KAT pubkey SHA3 from seed; Rust A24 (planned). | KAT · FORMAL (FIPS 205) | Same caveats. |
| **SHAKE256 / SHA3-512 output stability** | `@noble/hashes`; NIST FIPS 202. | KAT vectors; Rust A13 (planned). | KAT · FORMAL (FIPS 202) | Side-channel unassessed; `@noble` unaudited. |
| **HKDF-SHA-384 per-audience key isolation** — each (session, audience) pair yields a distinct key; a resource cannot derive a sibling audience's key from its own derived key. | `kernel/src/permit.ts`; ADR-0015; RFC 5869 HKDF-SHA-384. | KAT for derived key hex; CONF(C22); negative: wrong-audience token rejected. | KAT · CONF(C22) · TEST | Cryptographic isolation is sound; **key distribution obligation** (provision derived keys only, never the session master) is a deployment obligation, not protocol-enforced. |
| **dCBOR canonical encoding injectivity** — distinct values produce distinct canonical bytes; re-encoding is byte-stable. | `crypto/src/cbor.ts`; deterministic CBOR profile. | `crypto/test/cbor-determinism.test.ts` (PROP: injectivity + round-trip + key-order independence). | PROP · TEST | No cross-SDK differential fuzzing yet; injectivity proven only over fast-check's generated input space. |
| **dCBOR parser safety** — decoder never panics or throws uncaught exceptions on hostile input. | `crypto/src/cbor.ts`; A2 fuzz target (planned). | A2 fuzz: random/truncated bytes produce value or typed error, never uncaught throw. (planned) | FUZZ (planned) | Not yet implemented. Row is LOGIC-only until A2 lands. |

---

## Layer 2: Zero-Knowledge Layer

| Guarantee | Mechanism | Substantiation | Verification method | Honest scope |
|---|---|---|---|---|
| **Pedersen commitment perfect hiding** — commitment reveals zero information about v, even to an unbounded or quantum adversary. | Pedersen algebraic structure: C = v·G + r·H, r uniform. | Standard algebraic / information-theoretic argument. | FORMAL (algebraic) | **Perfect hiding is unconditional and post-quantum.** Holds for any generator pair, even a maliciously chosen H. Amount confidentiality is independent of generator provenance. |
| **Pedersen commitment computational binding** — no efficient adversary opens a commitment to two distinct (v, r) pairs. | ristretto255 prime-order group; NUMS-derived H (ADR-0016). | ADR-0016 NUMS argument; load-time invariant `assertGeneratorsWellFormed()` (planned); KAT C24 (planned). | LOGIC · KAT (planned) | **Classical assumption only** — reduces to discrete-log on ristretto255. A quantum computer with a discrete-log oracle breaks binding. QROM analysis of the Pedersen binding assumption is not done and is a labeled gap. |
| **Generator-H provenance and drift detection** — H is derived from a fixed public NUMS seed; any silent change to H (seed, library, encoding) is caught at build-time (KAT) and load-time (invariant). | `disclosure/src/generators.ts` (planned); seed `"PolarSeek/disclosure/generator-H/v1"`; `assertGeneratorsWellFormed()` (planned); KAT C24 (planned). | ADR-0016 design; invariants: H valid, H matches pin, H ≠ G, H ≠ O, H ≠ identity. | LOGIC (current) · KAT (planned) | **Not yet implemented.** Pinning checks well-formedness; does NOT prove dlog_G(H) is unknown — that remains a heuristic ROM assumption. |
| **ZK range proof soundness (classical)** — a proof `amount ∈ [0, threshold)` verifies only if the prover knows such an opening; forging requires breaking discrete log. | `disclosure/src/zkrange.ts`; dual-range CDS OR-proof; n ≤ 251 cap (ZKRANGE-002 fix). | CONF(C11); `zkrange.property.test.ts`; ZKRANGE-002 regression; ADR-0017 soundness argument. | PROP · CONF(C11) · LOGIC | **UNAUDITED; CLASSICAL (discrete-log + ROM); NOT QROM.** ZKRANGE-002 off-by-one caught and fixed 2026-06-21. External audit is the next gate. |
| **ZK range proof zero-knowledge (classical)** — the proof reveals nothing about `amount` beyond its range. | CDS OR-proof HVZK simulator; perfectly-hiding Pedersen commitments. | ADR-0017 HVZK argument; `zkrange.property.test.ts`. | LOGIC · PROP | **Classical ROM.** HVZK programs the random oracle. FS ZK in the QROM is not analyzed. Amount confidentiality is information-theoretic regardless (see hiding row above). |
| **Fiat-Shamir transcript binding (current, per-bit)** — challenge binds full statement (all bit commitments + params + per-bit first-messages); weak-FS / Frozen-Heart class partially closed. | `statementHash` + per-bit `challenge` in `zkrange.ts`. | ADR-0017 analysis §(c). | LOGIC | **Gap flagged for auditors:** generators G, H are not currently hashed into the transcript; per-bit challenges do not jointly bind all bits' first-messages. The ADR-0017 v3 tightening (single-transcript binding) closes this gap. Pending external audit ruling before implementation. |
| **Fiat-Shamir single-transcript tightening (v3, proposed)** — one root challenge binds all first-messages, all bit commitments, and generator bytes jointly; Frozen-Heart checklist passes cleanly. | ADR-0017 §(c) proposed v3 tightening; `statementHash` v3; single-pass commit-then-challenge. | ADR-0017 LOGIC argument; implementation and KAT pending audit approval. | LOGIC (design only) | **Not implemented; audit-gated.** Proposed, not ratified. |
| **n ≤ 251 no-wraparound bound** — for ristretto255 (L = 2^252 + d, d ≈ 2^124.7), requiring n ≤ 251 ensures 2^(n+1) ≤ L so bit recomposition sums cannot alias mod L. | `proveBelow`/`verifyBelow` hard cap n ≤ 251 (ZKRANGE-002). | `zkrange.test.ts` ZKRANGE-002 regression; ADR-0017 §(d) argument. | TEST · LOGIC | **Arithmetic is correct given L > 2^252.** Flagged as a priority external audit item because one off-by-one (n=252) already occurred. The bound must be verified by independent arithmetic, not trusted from this codebase. |
| **PSP soundness** — a PSP verifies only if `amount ≤ ceiling` (and `aggregate + amount ≤ cap`) for the committed amount; same opening binds both clauses. | `disclosure/src/policyproof.ts`; composes two range proofs (ADR-0006). | CONF(C13); `policyproof.test.ts`. | CONF(C13) · TEST | **UNAUDITED protocol composition.** Inherits range proof soundness (classical/ROM). Linkage contract (issuer commits the correct decided amount) is a deployment obligation. |
| **Commitment-to-intent binding** — `boundIntentDigest` binds the Pedersen commitment bytes into the signed receipt; a commitment substitution is detectable. | `disclosure/src/commitbind.ts`; ADR-0013; CB-001 fix (amount omitted from digest). | CONF(C21). | CONF(C21) · TEST | **UNAUDITED.** Does not defend against a kernel malicious at admission. |

---

## Layer 3: Consensus / Ledger Layer

| Guarantee | Mechanism | Substantiation | Verification method | Honest scope |
|---|---|---|---|---|
| **VRF leader sortition determinism and uniqueness** — each (prevHash, round) yields a unique VRF output that uniquely identifies the leader. | `ledger/src/leader.ts`; ECVRF (RFC 9381). | A9 planned property test: determinism, uniqueness, key-binding, 1-byte tamper rejection. | PROP (planned, A9) | VRF RFC 9381 is standardized; the ristretto VRF variant is unaudited. |
| **View-change cert quorum soundness** — a cert is accepted iff ≥ 2/3 stake of distinct, suite-matched, signature-valid votes for the correct (height, prevHash, round). | `ledger/src/leader.ts` `verifyViewChangeCert`; BigInt cross-multiply (LEDGER-PRECISION-002). | `ledger/test/vrf-chain.test.ts`; A12 negative tests (sub-2/3, dup-vote, cross-prevHash) planned. | TEST (partial) · CONF (C24 planned) | Stateless verifier. Does not detect a colluding ≥ 2/3 that legitimately signs a bad cert. |
| **View-change cert chain linearity — LEDGER-007 fix** — skipping N rounds requires N independently-signed chained certs; a lone high-round cert is rejected. | `verifyViewChangeCertChain` (planned); `prevCertDigest` link; ADR-0019. | ADR-0019 design; planned CONF(C24); planned negative tests (lone high-round cert, broken link, cross-fork splice, sub-2/3 intermediate, missing cert). | LOGIC · CONF (planned) | **DESIGN ONLY, NOT IMPLEMENTED.** Cert availability is an open design question (see CONSENSUS-CAVEATS.md). Constrains fairness; does not make skipping impossible for a willing ≥ 2/3. |
| **Validator-set binding on consensus messages** — consensus messages include a validator-set commitment so they cannot be replayed against a different epoch. | ADR-0020. | ADR-0020 design and implementation. | TEST | Per ADR-0020 status. |
| **Equivocation detection and slash evidence** — a validator signing conflicting attestations at the same height produces detectable, slash-eligible evidence. | `ledger/src/equivocation.ts`. | A27 planned property test: honest never flagged; double-signer flagged once. | PROP (planned, A27) | Detection only; slashing requires governance / execution outside Nerion. |
| **Accountable BFT safety** — with ≥ 2/3 honest stake, two conflicting finalized blocks at the same height are impossible without detectable equivocation. | ≥ 2/3 attestation threshold; round omitted from `attestMessage` (LEDGER-EQUIV-001). | `vrf-chain.test.ts` finality tests. | TEST | Classical BFT assumption. Not formally model-checked. |
| **Transparency-log append-only consistency** — every logged decision is in an append-only Merkle log; split-views are detectable. | `translog/src/`; RFC 6962-style Merkle log. | CONF(C10); Merkle soundness test (forged root rejected). | TEST · CONF(C10) | Single-operator log without external gossip; split-view detection, not prevention. |

---

## Layer 4: Protocol Composition

| Guarantee | Mechanism | Substantiation | Verification method | Honest scope |
|---|---|---|---|---|
| **Default-deny admission (fail-closed)** — any unexpected condition or exception yields `deny`. | `kernel/src/kernel.ts` `decide()` catch-all; PS-KERNEL-02. | CONF(C8); Team Apex 2026-06-21 validated no fail-open path. | TEST · CONF(C8) | Enforcement at admission only; actuator must honor the permit. |
| **Capability attenuation monotonicity** — a delegated grant narrows, never widens, the parent. | `capabilities/src/grant.ts` `narrow()` / `isAttenuationOf()`. | PROP: randomized "child authorizes ⇒ parent authorizes". | PROP · TEST | Sybil-resistance of the signer set is outside Nerion. |
| **Salted intent-commitment hiding** — the public log leaf does not leak a low-entropy amount via brute-force. | ADR-0014; RCPT-001 fix; per-receipt high-entropy salt; SHA3 over canonical{domain, salt, intent}; salt off-leaf. | CONF(C23). | TEST · CONF(C23) | Classical / ROM. Salt off-leaf protects the leaf; adversary with the salt recovers amount. |
| **Per-audience permit key isolation** | ADR-0015; PERMIT-001 fix; HKDF-SHA-384. | CONF(C22). | CONF(C22) · TEST | See Layer 1 HKDF row for deployment obligation. |
| **Govern-the-verb invariance** | Negative oracle; `ps-negative.json`; C14. | CONF(C14). | CONF(C14) | Pre-FTO. Runtime fence only; not a legal claim. |

---

## Guarantees absent from the base P0–P4 matrix that auditors expect

The following properties are NOT substantiated by existing evidence and represent gaps an external
auditor or dissertation committee would flag. They are the primary motivation for this extended matrix.

1. **QROM soundness of the Fiat-Shamir transform** — FS soundness in the quantum random-oracle model
   (QROM) is not analyzed for Nerion's range proofs. A quantum adversary making superposition queries to
   SHA3-512 may break soundness. Verification method required: **EXT-AUDIT + FORMAL**. This gap means
   the ZK soundness leg is labeled classical and any quantum forger of range proofs is unaddressed.

2. **Formal independence of G and H** — ADR-0016 correctly states that the NUMS argument justifies
   unknownness of dlog_G(H) heuristically in the ROM but provides no formal independence proof, and no
   efficient test exists. Verification method required: **LOGIC** (heuristic only, permanent unless a
   formal independence result exists for hash-to-curve). This is the root assumption of all commitment
   binding and is the single most load-bearing unproven claim in the protocol.

3. **Single-transcript FS tightening** — generators G, H not in the current challenge hash; per-bit
   challenges do not jointly bind all first-messages. ADR-0017 documents the gap and proposes a fix.
   Verification method required: **EXT-AUDIT** before implementation.

4. **n ≤ 251 arithmetic bound audit** — One off-by-one (n=252) has already occurred. The exact
   arithmetic argument (2^(n+1) ≤ L for n ≤ 251, with L = 2^252 + d) must be independently verified.
   Verification method required: **EXT-AUDIT** (independent arithmetic check).

5. **Cert availability for ADR-0019 chain linearity** — Without a resolved availability protocol for
   intermediate certs, the linearity property is unenforceable at verifier / light-client level.
   Verification method required: **LOGIC resolved** (open design question must be decided before
   ADR-0019 can be implemented).

6. **ML-DSA-87 QROM reduction in Nerion's usage context** — The QROM reduction for ML-DSA-87 exists
   in the academic literature (EUROCRYPT 2018) but has not been analyzed for Nerion's specific usage
   (key reuse across sessions, batch verification, composition with ZK proofs). Verification method
   required: **EXT-AUDIT**.

7. **Side-channel resistance** — No timing, fault-injection, or power-analysis assessment has been done
   for any primitive. Verification method required: **EXT-AUDIT** (hardware / implementation level).

8. **Canonical vote set collision resistance** — ADR-0019's `canonicalVoteSet` must be injective over all
   distinct honest quorums. The argument follows from SHAKE256 collision resistance (128-bit security)
   but is not stated explicitly. Verification method required: **LOGIC** (should be stated explicitly
   in ADR-0019).

---

## Verification method coverage summary

| Method | Coverage | Gap |
|---|---|---|
| KAT | Good for primitives (ML-DSA, ML-KEM, SLH-DSA, SHAKE256, HKDF, dCBOR); partial for composition | Generator-H KAT (C24) planned but not done |
| PROP | Attenuation, quorum receipts, range proof, Merkle; VRF / equivocation planned | Several key items planned, not yet implemented |
| CONF (C1–C23) | All implemented planes covered | C24 (cert chain) planned |
| FUZZ | dCBOR decoder, Rust AEAD — planned | Largely not yet implemented |
| LOGIC (ADR) | ZK soundness, NUMS, BFT, FS binding | Not externally verified; cannot substitute for EXT-AUDIT |
| EXT-AUDIT | **NONE completed** | P0 gap: all ZK, QROM, side-channel, integer bounds, cert availability |
| FORMAL | FIPS 204/203/205 algorithms only | Composition, QROM, BFT safety not formally verified |

---

*This document is a living artifact. It MUST be updated when the external audit completes, when new
ADRs land, or when conformance checks are added. The base `docs/ASSURANCE.md` remains the authoritative
claims matrix; this document is the deeper artifact-level evidence map for auditors.*

---

## PhD Panel Sprint 1 addendum — verification-method depth review (2026-06-24)

This section records the findings of the Track-B PhD panel (Mistral Large as PhD-seat reviewer,
cross-checked by Claude Sonnet 4.6 as orchestrator) from Sprint 1 (2026-06-24). It adds precision
to the verification-method column for the five highest-priority items. Nothing here changes the
status of any row above — it deepens the honest gap analysis.

### ADR-0016 (B1): Generator-H provenance — PhD panel findings

**Design assessment:** The NUMS construction (hash-to-curve with a human-readable domain-separated
seed) is the correct approach and the ADR is well-specified. The load-time invariants (valid decode,
H matches pin, H != identity, H != G, G is BASE) are necessary and correct.

**Gaps the ADR correctly flags and PhD panel confirms:**

- **Subtraction attack surface**: H != G and H != identity are not sufficient to prevent H = G^a for
  a known scalar a. The NUMS construction is what closes this, not the inequality checks alone. The
  inequality checks remove the trivially-broken degenerate cases; the ROM/NUMS argument is what
  eliminates the general discrete-log trapdoor. ADR-0016 is correct in its scope: it provides the
  checks it claims and documents the residual assumption honestly.

- **No efficient unknownness test**: The load-time invariant cannot verify that dlog_G(H) is unknown
  (no efficient algorithm exists for this). This is correctly flagged in ADR-0016 as an audit
  obligation, not a code obligation.

- **KAT is necessary but not sufficient**: Pinning H_PINNED_HEX prevents silent drift; it does NOT
  prove the pin itself is clean. An auditor must re-derive H from the public seed and the RFC 9380
  specification independently, verifying the hash-to-curve is applied faithfully.

**PhD panel recommendation:** Add a note to ADR-0016 that G and H bytes MUST be bound into the FS
challenge hash (ADR-0017 tightening gap c-1) because if they are not, a future code path with a
parameterized H could silently reuse challenges across different generators. This is low-risk defense
in depth, not a fix for a known break.

**Verification method for this guarantee (updated):** KAT (PROPOSED) + CONF C24 (PROPOSED) + ROM-ARG
(UNAUDITED) + EXT-AUDIT (REQUIRED before production). The "unknownness of dlog_G(H)" sub-assumption
has no verification method stronger than ROM-ARG.

### ADR-0017 (B2): ZK transcript soundness — PhD panel findings

**Design assessment:** The dual-range CDS OR-proof structure is standard and the 2-special-soundness
extraction argument in ADR-0017 section (a) is correctly stated. The ZKRANGE-002 fix (n <= 251) is
arithmetically correct given L = 2^252 + d (d > 0), since 2^{n+1} <= 2^252 < L for n <= 251.

**Key mathematical precision points:**

- **Soundness error for per-bit binding**: For a k-bit range proof with per-bit challenges drawn from
  a challenge space of size |C|, the soundness error per bit is 1/|C|. With SHAKE256 challenges
  (256-bit challenge space), this is negligible. Per-bit challenges do NOT degrade soundness to 2^{-k}
  (the 2^{-k} figure would apply if the prover could choose the challenge bits, not if the challenges
  are derived from a random oracle). ADR-0017 is correct on this point.

- **QROM gap**: Fiat-Shamir's soundness in the QROM requires a quantum-accessible hash function with
  reprogramming resistance. SHAKE256 as a quantum random oracle does admit Unruh's transform analysis,
  but this has not been done for this specific construction. The gap is correctly labeled in ADR-0017
  and in the table above.

- **OR-proof HVZK under XOR vs AND challenges**: ADR-0017 uses the CDS construction where c_0 + c_1 = c
  (additive split over the scalar field, not XOR over bits). This is the correct CDS form and preserves
  HVZK. XOR-split would NOT be HVZK in general because the simulator cannot independently program
  both sub-challenges to sum to a randomly-programmed c. ADR-0017 is correct.

**PhD panel recommendation:** The single-transcript tightening (v3) remains the recommended path for
auditor certification. The current per-bit binding is assessed as probably sound for this specific
construction, but the tightening removes ambiguity at minimal implementation cost.

### ADR-0018/ADR-0019 (B3): View-change cert chain — PhD panel findings

**Design assessment:** The chained ViewChangeCert design in ADR-0019 correctly makes round-skipping
O(N) in verification cost. The per-link >=2/3 quorum threshold is correct for BFT safety (not f+1,
which is only sufficient for liveness; 2f+1 = >=2/3n ensures no two valid quorums can disagree).

**Key BFT precision points:**

- **Quorum threshold**: 2/3 + epsilon for distinct, non-equivocating validators is the correct
  threshold for accountable BFT safety. f+1 is NOT sufficient against a Byzantine adversary; it only
  guarantees liveness (at least one honest node). ADR-0019 correctly uses the >=2/3 threshold per link.

- **Embedded data requirement**: The certDigest commits to (height, prevHash, round, prevCertDigest,
  voteSet). ADR-0019 correctly promotes height and prevHash onto the cert struct (section 3) to prevent
  cross-fork splicing. The last committed log index is NOT embedded (it is not in the current design).
  This is a known residual: if a malicious leader wants to truncate the log while constructing a valid
  chain, they cannot do so without forging >=2/3 signatures at each round (since finality is separately
  >=2/3-attested). Log truncation attacks are therefore gated by the same threshold as safety. This is
  acceptable for the current design scope but should be confirmed by the external audit.

- **Cert availability gap (critical)**: This remains the most significant unresolved design question.
  ADR-0019 correctly flags it. The PhD panel confirms: without cert availability guarantees, the
  linearity property is NOT enforceable at the light client. A block proposer can assert they have the
  chain; a verifier who cannot fetch intermediate certs must fail-closed, which can itself become a
  liveness vector. The resolution (carry-in-block vs gossip vs accumulator) MUST be decided before
  ADR-0019 can be implemented.

### ML-DSA-87 formal security memo — PhD panel findings

**Design assessment:** ML-DSA-87 (FIPS 204, k=8, l=7, eta=2) provides NIST security level 5
(>=256-bit classical, >=128-bit quantum). The underlying hardness assumptions are Module-LWE for
key-recovery resistance and Module-SIS for existential unforgeability (EU-CMA). Both are well-studied
lattice problems with no known classical or quantum polynomial-time algorithms.

**ROM vs QROM gap (precise):** ML-DSA's Fiat-Shamir-with-aborts construction is proven EU-CMA secure
in the ROM under Module-LWE/SIS (Ducas-Durmus-Lepoint-Lyubashevsky, CRYPTO 2018). A QROM security
proof exists (Kiltz-Lyubashevsky-Schaffner, EUROCRYPT 2018) but the reduction is not perfectly tight:
the QROM proof requires slightly larger parameters or accepts a small tightness loss. For ML-DSA-87
specifically, the NIST-selected parameters provide sufficient margin that this tightness loss does not
affect the claimed security level in practice. However, Nerion has not formally analyzed the tightness
loss in its specific deployment context (key reuse, session-bound usage, composition with ZK proofs).

**Residual formal analysis gaps:**
1. EU AI Act + NIST AI RMF: Nerion is infrastructure, not an AI system per the Act. ML-DSA-87 is an
   appropriate choice for a post-quantum infrastructure component. Algorithm agility documentation is
   needed (ADR gap, not a FIPS gap).
2. Side-channel resistance: Not addressed by FIPS 204 or any current Nerion document. Required for
   production hardware deployments.
3. QROM composition: The ZK layer (classical soundness) and the ML-DSA-87 layer (QROM-analyzed
   signatures) have different post-quantum profiles. The composition is not formally analyzed. The
   honest framing: receipt integrity is PQ (ML-DSA-87); ZK soundness is classical; amount confidentiality
   is information-theoretic/PQ. These three legs are correctly documented in ASSURANCE.md but the
   composition is unaudited.

### A39-EXTENDED matrix design — PhD panel recommendations

**Verification methods not yet in the matrix that should be added for completeness:**

| Method | Use case | Status |
|---|---|---|
| TLA+/PlusCal | BFT consensus safety/liveness model | Not planned; recommended for ADR-0019 post-audit |
| EasyCrypt | ZK range proof soundness mechanized proof | Not planned; stretch goal post external audit |
| Cryptol | ML-DSA-87 implementation correctness | Not planned; stretch goal |
| PROVERIF/Tamarin | Quorum receipt protocol, transparency log | Not planned; stretch goal |

**Honest framing from the PhD panel**: The gap between "KAT passes" and "formally proven secure" is
large. For the ZK layer specifically: KAT proves the implementation matches the spec's own vectors;
PROP proves an invariant over a generated input space; ROM-ARG is a manual argument that could
contain errors; EXT-AUDIT is the first independent check; only EasyCrypt/Coq provides machine-checked
confidence. Nerion is currently at PROP + ROM-ARG for the ZK layer, which is appropriate for the
current maturity level but must not be confused with the later tiers.

---

*PhD Panel Sprint 1 addendum added 2026-06-24 by orchestrator (Claude Sonnet 4.6) based on Mistral Large
PhD-seat review. Not a security result. Routes to the external ZK/crypto audit.*
