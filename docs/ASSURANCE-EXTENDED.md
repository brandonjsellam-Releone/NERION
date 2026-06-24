<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion — Extended Assurance Matrix (A39-EXTENDED)

**Purpose.** This document supplements `docs/ASSURANCE.md` with a denser
**guarantee × artifact × verification-method** matrix. Each row names a concrete
cryptographic or protocol-level security guarantee, the in-repo artifact (code,
ADR, KAT, test, or proof sketch) that is supposed to deliver it, and the
verification method(s) applied. A separate column records whether any cell is
currently **unverifiable** — no artifact, no test — which is the signal that
flags an audit gap.

Produced by the Nerion R&D PhD Panel (Sprint 1, 2026-06-24). This is a
**design document, not a security result**. Nothing here is audited, FIPS-
validated, or a non-infringement claim. Every "UNAUDITED" label is intentional
and load-bearing — do not remove without a completed independent audit.

**Evidence tiers used in this matrix (inherited from ASSURANCE.md):**

| Symbol | Meaning |
|---|---|
| `P` | Formal proof in a published paper or verified model |
| `F` | Mechanized / machine-checked proof (Coq, Lean, EasyCrypt, etc.) |
| `A` | External independent audit report exists |
| `R` | ROM/QROM security argument written down (internal, unaudited) |
| `K` | Known-Answer Test (pinned deterministic vector) |
| `T` | Automated regression / example-based test |
| `PT` | Property-based / randomized test (fast-check / proptest) |
| `C` | In-repo conformance-suite check (Nerion's own spec — conformant ≠ validated) |
| `N` | No artifact / no test — explicit gap |

**Verification columns (matrix header):**

1. **Formal proof** — published/mechanized reduction
2. **ROM argument** — informal written security argument in ROM
3. **KAT** — deterministic known-answer test vector
4. **Property test** — randomized invariant test
5. **Conformance** — in-repo `npm run conformance` check
6. **Regression test** — automated example-based test
7. **Unverifiable gap** — cell is `N` (no artifact/test exists yet)

---

## Section 1 — Zero-Knowledge Layer Guarantees

| # | Guarantee | Artifact | Formal proof | ROM argument | KAT | Property test | Conformance | Regression | Gap / Notes |
|---|---|---|---|---|---|---|---|---|---|
| ZK-1 | **Pedersen commitment is perfectly hiding** — `commit(v, r) = v·G + r·H` reveals nothing about `v` for any choice of `H` (even adversarially chosen), because `r` is uniform over the full scalar group | `disclosure/src/zkrange.ts:70-72` | `P` — standard Pedersen over prime-order group; unconditional (information-theoretic) | — | — | — | — | — | Hiding is **unconditional / information-theoretic** — no discrete-log assumption needed; PQ-safe |
| ZK-2 | **Pedersen commitment is computationally binding** — opening is unique up to discrete-log hardness: no PPT adversary can find `(v', r') ≠ (v, r)` with the same commitment, provided `dlog_G(H)` is unknown | `disclosure/src/zkrange.ts`; `ADR-0016` | `N` — hardness reduction to DLOG not written out; reduction is standard but unlabeled | `R` — ADR-0016 §soundness argument | `K` — H_PINNED_HEX in ADR-0016 (planned; not yet in ps-kat.json) | — | `N` — planned C24 (not yet) | `N` — generators.test.ts planned (not yet) | **Critical:** DLOG assumption is **classical only** — quantum adversary breaks binding; QROM not analyzed (FORMAL-SECURITY gap) |
| ZK-3 | **`dlog_G(H)` is unknown** — the NUMS construction guarantees no party possesses a trapdoor `t` with `H = t·G` | `ADR-0016 §(a)`; DST `"ristretto255_XMD:SHA-512_R255MAP_RO_"` | `N` — no formal proof; heuristic ROM argument only | `R` — ADR-0016 §(a) residual assumption | — | — | — | — | **Not provable at runtime**; heuristic NUMS argument only; external audit obligation |
| ZK-4 | **Generator H is well-formed at load time** — H ≠ identity, H ≠ G, H has prime order, H matches pinned bytes | `ADR-0016 §(c)` invariants 1–6; planned `disclosure/src/generators.ts` | — | `R` — ADR-0016 §(c) | `K` — planned KAT vector | — | `N` — planned C24 | `N` — planned `generators.test.ts` | Startup invariants specified in ADR-0016; **not yet implemented** |
| ZK-5 | **Per-bit OR-proof is 2-special-sound** — from two transcripts sharing the same first message with distinct challenges, an extractor recovers a genuine bit-witness (b_i ∈ {0,1}) | `disclosure/src/zkrange.ts` (`proveBit`/`verifyBit`); `ADR-0017 §(a)` | `N` — no published/mechanized reduction | `R` — ADR-0017 §(a) written argument | — | `PT` — `zkrange.property.test.ts` | `C` — C11 | `T` — `zkrange.test.ts` | **Grok PhD finding:** per-bit extraction argument is self-consistent; extraction error is 1/|challenge_space| per bit — negligible for ≥128-bit challenges; QROM not addressed |
| ZK-6 | **OR-composition is HVZK** — simulator produces transcripts identically distributed to honest ones without the witness, using CDS false-clause pre-commitment | `ADR-0017 §(b)` | `N` | `R` — ADR-0017 §(b) | — | `PT` — `zkrange.property.test.ts` | `C` — C11 | `T` | Simulator argument written; unconditional ZK (Pedersen perfectly hiding) — **hiding survives quantum adversaries** |
| ZK-7 | **Fiat-Shamir transcript is not malleable** — the challenge binds the full statement (all bit commitments, both sub-proofs, params); Frozen Heart class closed | `zkrange.ts:statementHash`; `ADR-0017 §(c)` | `N` | `R` — ADR-0017 §(c) | — | `N` | `C` — C11 (partial) | `T` | **Gap flagged by Grok PhD:** generators G and H are NOT currently hashed into the transcript; single-transcript binding (tightening proposed in ADR-0017) pending audit ratification |
| ZK-8 | **No wraparound in range recomposition** — `Σ b_i·2^i ∈ [0, 2^n)` holds over the integers (not mod L), for n ≤ 251 | `zkrange.ts` n≤251 cap; `ADR-0017 §(d)`; ZKRANGE-002 fix | `N` | `R` — ADR-0017 §(d) | `K` — existing `ps-kat.json` range vectors | `PT` | `C` — C11 | `T` | Priority audit item — one off-by-one already found (ZKRANGE-002); `n+1` margin argument must be verified externally |
| ZK-9 | **Dual-range soundness** — proving BOTH `amount ∈ [0,2^n)` AND `diff = threshold-1-amount ∈ [0,2^n)` is strictly necessary; single-range sufficiency proof | `zkrange.ts` dual-range structure; `ADR-0006` | `N` | `R` — ADR-0006 / ADR-0017 | — | `PT` | `C` — C11 / C13 | `T` | `diff` commitment is **verifier-reconstructed** (load-bearing — prevents prover from supplying a dishonest `C_diff`) |
| ZK-10 | **OR-proof soundness in QROM** — the Fiat-Shamir transform applied to the CDS OR-proof is sound against quantum adversaries querying the random oracle in superposition | `N` — no quantum analysis exists | `N` | `N` | `N` | `N` | `N` | **CRITICAL UNVERIFIABLE GAP** — quantum adversary can break soundness/binding; amount hiding remains safe (perfectly hiding), but proof integrity does not |

---

## Section 2 — Commitment and Binding Guarantees

| # | Guarantee | Artifact | Formal proof | ROM argument | KAT | Property test | Conformance | Regression | Gap / Notes |
|---|---|---|---|---|---|---|---|---|---|
| CB-1 | **v:2 commitment-to-intent binding** — the public `boundIntentDigest` is a SHA3 pre-image that binds `commit(amount,r).toBytes()` so the issuer cannot substitute a different amount after commitment | `disclosure/src/commitbind.ts`; `ADR-0013`; CB-001 fix | `N` | `R` — ADR-0013 | `K` — `ps-kat.json` | `PT` | `C` — C21 | `T` | CB-001 FIXED: amount was previously in the digest pre-image (bruteforceable); now omitted, bound only by the perfectly-hiding commitment |
| CB-2 | **Salted intent commitment log-leaf hiding** — the v:1 log leaf uses `SHA3(canonical{domain, salt, intent})` so a low-entropy amount cannot be brute-forced from the public leaf | `ADR-0014`; RCPT-001 fix | `N` | `R` — ADR-0014 | — | — | `C` — C23 | `T` | Salt carried off-leaf; classical/ROM; hiding applies to the leaf **not** to the full disclosure path |
| CB-3 | **Canonical encoding injectivity** — distinct logical values produce distinct dCBOR bytes; no two distinct values share a canonical encoding | `crypto/src/cbor.ts`; `crypto/test/cbor-determinism.test.ts` | `N` | `R` — dCBOR spec | `K` — existing CBOR KATs | `PT` | — | `T` | No cross-SDK fuzzing / differential harness yet |

---

## Section 3 — Quorum Receipt and Threshold Guarantees

| # | Guarantee | Artifact | Formal proof | ROM argument | KAT | Property test | Conformance | Regression | Gap / Notes |
|---|---|---|---|---|---|---|---|---|---|
| QR-1 | **k-of-n quorum finalization** — a receipt finalizes iff ≥k distinct valid member signatures over a fixed named signer set are presented | `receipts/src/quorum.ts`; `ADR-0005` | `N` | `R` — ADR-0005 | `K` — `ps-kat.json` | `PT` — `quorum.property.test.ts` | `C` — C12 | `T` | Proves quorum **signed**, not that signers are independent / Sybil-resistant |
| QR-2 | **Set-binding in quorum receipts** — the quorum is bound to a named, fixed signer set; a receipt from a different signer set or a permutation of signers does not cross-verify | `receipts/src/quorum.ts`; `ADR-0020` | `N` | `R` — ADR-0020 | — | `PT` — set-substitution rejection test | `C` — C12 | `T` | **Gap flagged by Grok PhD:** binding to participant identity set in threshold receipts is tested but the formal binding definition is not written out — see CONSENSUS-CAVEATS.md §set-binding |
| QR-3 | **Per-audience HKDF permit key isolation** — each resource is provisioned with only its HKDF-derived audience key; a key-holding resource cannot re-MAC a different-audience permit | `capabilities/`; `ADR-0015`; PERMIT-001 fix | `N` | `R` — ADR-0015 | `K` — `ps-kat.json` | — | `C` — C22 | `T` | Correct key distribution is a deployment obligation, not a protocol guarantee |

---

## Section 4 — Consensus and Ledger Guarantees

| # | Guarantee | Artifact | Formal proof | ROM argument | KAT | Property test | Conformance | Regression | Gap / Notes |
|---|---|---|---|---|---|---|---|---|---|
| CL-1 | **VRF leader sortition unpredictability** — the VRF output is unforgeable and unpredictable to validators who do not hold the leader's private key | `ledger/src/leader.ts`; `ADR-0004` | `N` | `R` — ADR-0004 | `K` — VRF KATs | — | — | `T` — `vrf-chain.test.ts` | ML-DSA-87 VRF; security reduces to MLWE/MSIS (classical + QROM with tightness gap — see FORMAL-SECURITY) |
| CL-2 | **View-change certificate quorum integrity** — a ViewChangeCert is valid iff ≥2/3 distinct stake-weighted validators signed a TimeoutVote for the same `(height, prevHash, round)` | `ledger/src/leader.ts:verifyViewChangeCert`; `ADR-0004` | `N` | `R` — ADR-0004 | — | — | — | `T` — `vrf-chain.test.ts` | Current threshold uses BigInt cross-multiply (LEDGER-PRECISION-002); stateless verifier |
| CL-3 | **Round-skip cost is linear (chained ViewChangeCert)** — advancing N rounds requires N independently-quorum-signed certs; LEDGER-007 fairness gap closed | `ADR-0019` (PROPOSED, not yet implemented) | `N` | `R` — ADR-0019 §soundness sketch | `N` — no KAT yet | `N` | `N` — planned C24 | `N` | **Biggest open gap in CL:** cert-availability residual unresolved; digest canonicalisation must be audited; Grok PhD: quorum threshold MUST be 2f+1 (not t+1), confirmed in ADR-0019 |
| CL-4 | **Equivocation slashing comparability** — same-height attestations from all rounds are equivocation-comparable; round is deliberately excluded from `attestMessage` | `ledger/src/equivocation.ts`; `docs/SECURITY_FINDINGS.md` LEDGER-EQUIV-001 | `N` | `R` — SECURITY_FINDINGS | — | — | — | `T` | Interaction with ADR-0019 chaining verified to be safe (LEDGER-EQUIV-001 adjudication recorded in ADR-0019) |
| CL-5 | **Transparency-log append-only consistency** — an appended Merkle log cannot be silently rewritten; split-view detection is included | `translog/src/`; RFC 6962 style | `N` | `R` — RFC 6962 / SCITT | — | — | `C` — C10 | `T` — `merkle-soundness.test.ts` | Single-operator log unless externally gossiped; split-view **detection** not prevention |

---

## Section 5 — Post-Quantum and ML-DSA-87 Guarantees

| # | Guarantee | Artifact | Formal proof | ROM argument | KAT | Property test | Conformance | Regression | Gap / Notes |
|---|---|---|---|---|---|---|---|---|---|
| PQ-1 | **ML-DSA-87 unforgeability (classical)** — no PPT adversary can forge a valid ML-DSA-87 signature without the signing key, under MLWE + MSIS assumptions | `crypto/`; FIPS 204 | `P` — FIPS 204 security argument (ROM) | `R` — ADR-0001 / ADR-0025 | `K` — NIST KATs | — | `C` — C1–C5 | `T` | Algorithm-compatible; **NOT FIPS-validated** (no CMVP) |
| PQ-2 | **ML-DSA-87 unforgeability (QROM)** — same guarantee against a quantum adversary querying the random oracle in superposition | `N` — not analyzed for Nerion's usage | `N` | `N` | `N` | `N` | `N` | **Gap flagged by Grok PhD:** MLWE/MSIS are sound in QROM (Kiltz et al. 2018; post-quantum security proven for Dilithium/ML-DSA), but the reduction has a **tightness gap** — the concrete quantum security level is lower than the classical level. The residual gap has NOT been analyzed for Nerion's specific usage. |
| PQ-3 | **No nonce-reuse failure mode** — ML-DSA-87 uses deterministic signing (FIPS 204 hedged variant); no per-signature randomness requirement that could fail under RNG weakness | `crypto/`; FIPS 204 | `P` — FIPS 204 deterministic variant | `R` | `K` | — | — | `T` | Hedged (randomized) variant also defined in FIPS 204 — Nerion must document which variant is in use and confirm the KAT vectors match |
| PQ-4 | **Hybrid KEM forward secrecy** — ML-KEM-1024 + P-384 hybrid provides forward secrecy; compromise of long-term keys does not expose past sessions | `crypto/`; `ADR-0002` | `N` | `R` — ADR-0002 | `K` | — | `C` | `T` | **Known caveat:** P-384 leg is quantum-vulnerable (CBOM flagged); hybrid KEM still provides classical forward secrecy; pure-PQ forward secrecy requires ML-KEM only |
| PQ-5 | **CNSA 2.0 alignment** — Nerion uses algorithm suites (ML-DSA-87, ML-KEM-1024, SHA-384+) that satisfy CNSA 2.0 category PS-5 / Cat-5 requirements | `ADR-0008`; CNSA oracle; `ADR-0025` | `N` | `R` — ADR-0008 / ADR-0025 | `K` — CNSA verdict KAT | — | `C` — C15/C16 | `T` | **"Transitional" not pure-CNSA** (hybrid KEM + SHA3); alignment ≠ NSA validation or approval |

---

## Section 6 — Governance and Protocol-Level Guarantees

| # | Guarantee | Artifact | Formal proof | ROM argument | KAT | Property test | Conformance | Regression | Gap / Notes |
|---|---|---|---|---|---|---|---|---|---|
| GP-1 | **Default-deny admission (fail-closed)** — `decide()` returns `deny` unless a verified capability authorized the intent; any throw denies at tier 3 | `kernel/src/kernel.ts`; `ADR-0007` | `N` | `R` — ADR-0007 | — | — | `C` — C8 | `T` — `kernel.test.ts` | Team Apex 2026-06-21 validated no fail-open path |
| GP-2 | **Govern-the-verb invariance** — admission decision is byte-identical under injection of any perception-shaped side-data | `conformance/src/negative.ts`; `ADR-0007` | `N` | `R` — ADR-0007 | `K` — `ps-negative.json` | — | `C` — C14 | `T` | pre-FTO; invariance is the design-around runtime fence, not a legal claim |
| GP-3 | **Capability attenuation never amplifies** — a delegated grant authorizes only a subset of its parent across every dimension | `capabilities/src/grant.ts` | `N` | `R` — capabilities design | — | `PT` — `attenuation.property.test.ts` | — | `T` | Monotone subset semantics; property-checked |

---

## Section 7 — Summary: Unverifiable Gap Inventory

The following guarantees currently have **no artifact or no test** (`N` in all verification columns). These are the rows an external auditor will flag first:

| Gap ID | Guarantee lacking verification | Recommended remediation |
|---|---|---|
| GAP-ZK-10 | OR-proof soundness in QROM | Commission formal QROM analysis (EasyCrypt / ProVerif) as part of the external ZK/crypto audit |
| GAP-ZK-3 | `dlog_G(H)` genuinely unknown | Cannot be proven at runtime; must be argued formally in the audit scope |
| GAP-ZK-7 | G and H not hashed into transcript | Implement ADR-0017 §(c)(1) tightening after audit ratification |
| GAP-CL-3 | Linear round-skip cost (chained ViewChangeCert) | Implement ADR-0019 after cert-availability residual is resolved; add C24 conformance check |
| GAP-PQ-2 | ML-DSA-87 QROM tightness gap analyzed for Nerion usage | Internal memo on concrete quantum security margin needed before production |
| GAP-QR-2 | Formal set-binding definition for threshold receipts | Write out the formal binding predicate in ADR-0005 and CONSENSUS-CAVEATS.md |
| GAP-CB-1 | DLOG reduction for Pedersen binding not written out | Write the standard reduction into ADR-0016 (or a new FORMAL-SECURITY memo) |
| GAP-PQ-3 | Confirm deterministic vs. hedged ML-DSA-87 variant in use | Audit the crypto/ KAT against FIPS 204 deterministic test vectors |

---

*This matrix is reviewed by the Nerion R&D PhD Panel (Sprint 1) and is
intended to be updated as gaps are closed. It is explicitly a living document —
an `N` cell means work remains, not that the guarantee is false. Conformant is
not validated; built is not audited; property-checked is not proven.*
