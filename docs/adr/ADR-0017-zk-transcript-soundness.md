<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0017 — ZK Transcript Soundness: Dual-Range OR-Proof

**Status: Proposed**

**Design only. No code, KAT vector, or behavioural change in this ADR.**
This document provides the formal security argument for the dual-range
Chaum–Pedersen OR-proof (CDS composition) used in `disclosure/src/zkrange.ts`,
as reviewed and synthesised by the DeepSeek PhD council seat (Sprint-1, item
ADR-0017). All arguments below are **ROM (classical, random-oracle model) only**;
the QROM residual risk is documented explicitly in the Consequences section. The
argument is **UNAUDITED** — it is a prerequisite *input* to the external ZK/crypto
audit that gates ADR-0006 and ADR-0013. No production privacy or soundness claim
is made here.

Date: 2026-06-24. Author: Nerion PhD council (DeepSeek seat synthesis).
Underlies conformance checks **C11** (range proof) and **C13** (policy-satisfaction
proof, ADR-0006).

---

## Context

`disclosure/src/zkrange.ts` proves, in zero knowledge, that a Pedersen commitment
`C = v·G + r·H` (over the audited prime-order ristretto255 group) hides a value
satisfying `0 ≤ amount < threshold`, without revealing `amount`. The construction
is a **dual-range bit-decomposition** with one CDS OR-proof per bit, made
non-interactive by Fiat–Shamir. A multi-model PhD council review (Sprint-1) of all
six high-priority items identified the **highest-severity finding** in this ADR:
the interaction between per-bit challenge binding and Sigma-protocol
special-soundness. That finding, and the corrective requirement, are the central
subject of this document.

### Construction summary (from `zkrange.ts`)

- **Pedersen commitment.** `commit(v, r) = v·G + r·H` where `G = Point.BASE` and
  `H` is a nothing-up-my-sleeve (NUMS) hash-to-curve point (ADR-0016); `L` is the
  prime ristretto255 group order.
- **Dual range.** Two sub-proofs run in parallel: (i) `amount ∈ [0, 2^n)` against
  the prover-supplied commitment `C_amt`; (ii) `diff = threshold − 1 − amount ∈ [0, 2^n)`
  against `C_diff = (threshold − 1)·G − C_amt` (reconstructed by the verifier from
  public data, never taken from the proof). Together over the integers they establish
  `0 ≤ amount < threshold` for `threshold ≤ 2^n`. Both bounds are required; the
  earlier single-range `diff`-only variant was unsound (an adversary could commit a
  mod-`L` wrapped value).
- **Bit decomposition.** Each sub-range is proven by committing the value bit by bit:
  `C_i = b_i·G + r_i·H` for `i = 0, …, n−1`, with `buildBits` ensuring
  `Σ_i C_i · 2^i = C_target` (homomorphic recomposition, verified by `verifySub`).
- **Per-bit OR-proof (CDS).** Each `C_i` is proven to commit to `b_i ∈ {0, 1}` via
  a 2-clause Chaum–Pedersen / Cramer–Damgård–Schoenmakers composition: the prover
  shows it knows `dlog_H(P_0)` OR `dlog_H(P_1)`, where `P_0 = C_i` (witness:
  `b_i = 0`) and `P_1 = C_i − G` (witness: `b_i = 1`). The CDS trick: the prover
  simulates the false clause `(sFake, cFake, tFake)` and runs the real clause
  honestly, with the split constraint `c_0 + c_1 = c` (mod `L`), where `c` is the
  Fiat–Shamir challenge for that bit.
- **Fiat–Shamir.** Non-interactivity is achieved via SHAKE256 in the random-oracle
  model. Two functions in `zkrange.ts` are relevant:
  - `statementHash(threshold, n, C_amt, amountC, diffC)` — binds `(n, threshold,
    C_amt,` all `2n` bit commitments`)` into a 64-byte statement digest `stmt`, mixed
    into every per-bit challenge.
  - `challenge(stmt, tag, C_i, P_0, P_1, t_0, t_1)` — per-bit challenge hash,
    binding `stmt`, the bit-index domain tag, the clause points, and that bit's own
    first messages `(t_0, t_1)`.

---

## Decision

1. **Record** the formal definitions of special-soundness and HVZK as they apply to
   the Nerion dual-range OR-proof.
2. **Establish** that per-bit challenge binding, as currently implemented, is
   **mathematically incompatible** with Sigma-protocol special-soundness across the
   full `2n`-bit composition, and that the correct construction requires a **single
   joint Fiat–Shamir challenge** over the complete transcript (full statement + all
   branch commitments + domain separator).
3. **Specify** the required single-scalar challenge construction (see Security
   Argument §3) as the normative transcript binding rule that any conforming
   implementation MUST produce.
4. **Document** the QROM residual risk (see Consequences).
5. **Ship no code.** This ADR is a formal design record and audit input. Implementation
   is gated on external ZK/crypto audit ratification.

---

## Formal Definitions

The following definitions are stated as they apply to the Nerion construction.
Notation: `G` is a cyclic prime-order group of order `L` (ristretto255); elements
are denoted by capital letters; scalars are mod `L`. "ROM" means the random oracle
model with SHAKE256 modelled as a programmable random oracle.

### Definition 1 — Sigma Protocol

A **sigma protocol** for relation `R = {(x, w) : x is a statement, w is a witness}`
is a three-move interactive proof `(P, V)` with moves `(a, e, z)`:

1. **Commit (first move).** The prover `P(x, w)` sends a commitment `a` (the
   "announcement" or "first message").
2. **Challenge.** The verifier `V(x)` sends a uniformly random challenge `e ∈ {0,1}^κ`.
3. **Response (third move).** The prover sends `z`; the verifier accepts iff the
   verification relation `V(x, a, e, z) = 1` holds.

The Chaum–Pedersen proof of knowledge of `dlog_H(P)` is the canonical sigma protocol
used per-clause in the Nerion OR-proof.

### Definition 2 — Special Soundness (2-Special-Soundness)

A sigma protocol is **2-special-sound** if there exists a polynomial-time extractor
`E` such that: given any two accepting transcripts `(a, e, z)` and `(a, e', z')` on
the **same first message** `a` with **distinct challenges** `e ≠ e'`, the extractor
outputs a witness `w` with `(x, w) ∈ R`.

As applied to the Nerion single-bit OR-proof for bit commitment `C_i`:

- Two transcripts sharing first messages `(t_0, t_1)` with distinct overall challenges
  `c ≠ c'` (mod `L`) allow extraction of `dlog_H(C_i)` (if `b_i = 0`) or
  `dlog_H(C_i − G)` (if `b_i = 1`), certifying `b_i ∈ {0, 1}`.

As applied to the **full `2n`-bit composition**: special-soundness for the
composite proof requires that two transcripts sharing ALL `2n` first-message vectors
`{(t^{(i)}_0, t^{(i)}_1)}_{i=0}^{2n−1}` with distinct **joint** challenges allow
witness extraction for all bits simultaneously. This requires a **single joint challenge**
that binds the entire first-message vector; it is not achievable with `2n` independent
per-bit oracle calls (see §3 below for the incompatibility argument).

### Definition 3 — Honest-Verifier Zero-Knowledge (HVZK)

A sigma protocol is **honestly-verifier zero-knowledge (HVZK)** if there exists a
polynomial-time simulator `S(x)` that, on input only the statement `x` (without the
witness), outputs transcripts `(a, e, z)` that are **identically distributed** to
transcripts produced by the honest prover interacting with an honest verifier.

In the Fiat–Shamir (non-interactive) setting, HVZK is achieved by giving the simulator
the ability to **program** the random oracle: it chooses `e` first, then constructs
`(a, z)` such that `V(x, a, e, z) = 1`. The CDS OR-proof simulator for a single bit
operates exactly this way (see §2 below).

---

## Security Argument (ROM, classical — UNAUDITED)

> **Convention.** `L = 2^252 + 27742317777372353535851937790883648493` (ristretto255
> group order). `G` = `Point.BASE`; `H` = NUMS hash-to-curve (ADR-0016), `dlog_G(H)`
> unknown. Scalar arithmetic is mod `L`. "ROM" = SHAKE256 modelled as a random oracle.
> All arguments are **classical** (not QROM). All claims are **UNAUDITED**.

### §1 — Special-Soundness of the Single-Bit OR-Proof

**Claim.** The single-bit OR-proof (`proveBit` / `verifyBit` in `zkrange.ts`) is
2-special-sound. From any two accepting transcripts on the same first message
`(t_0, t_1)` with distinct overall challenges `c ≠ c'` (mod `L`), an extractor
recovers either `dlog_H(C_i)` or `dlog_H(C_i − G)`, hence a witness certifying
`b_i ∈ {0, 1}`.

**Argument.**

Let `P_0 = C_i`, `P_1 = C_i − G`. The verifier's accept condition is:

```
(A)  c_0 + c_1 ≡ c  (mod L)
(B)  H^{s_0} = t_0 · P_0^{c_0}
(C)  H^{s_1} = t_1 · P_1^{c_1}
```

Take two accepting transcripts on the same `(t_0, t_1)`:

```
T  = (c_0,  c_1,  s_0,  s_1)  with c  = c_0  + c_1
T' = (c_0', c_1', s_0', s_1') with c' = c_0' + c_1'
```

Since `c ≠ c'` and `(c_0 + c_1) ≠ (c_0' + c_1')`, at least one index `j ∈ {0, 1}`
has `c_j ≠ c_j'`. Assume WLOG `c_0 ≠ c_0'` (the `c_1 ≠ c_1'` case is symmetric).
Both transcripts satisfy condition (B) on the same `t_0`:

```
H^{s_0}  = t_0 · P_0^{c_0}       ... (B)
H^{s_0'} = t_0 · P_0^{c_0'}      ... (B')
```

Dividing (B) by (B'):

```
H^{s_0 − s_0'} = P_0^{c_0 − c_0'}
```

Since `L` is prime and `c_0 − c_0' ≢ 0 (mod L)`, the scalar `(c_0 − c_0')` is
invertible mod `L`. The extractor outputs:

```
w = (s_0 − s_0') · (c_0 − c_0')^{−1}  mod L
```

This satisfies `H^w = P_0`, i.e. `w = dlog_H(C_i)`, certifying `b_i = 0`.
Symmetrically, `c_1 ≠ c_1'` yields `dlog_H(C_i − G)`, certifying `b_i = 1`. In
either case the extracted witness proves `b_i ∈ {0, 1}`. ∎

**Why the prime-order group is essential.** The step `(c_0 − c_0')^{-1} mod L`
requires `L` to be prime. On ristretto255, the group has prime order with no
cofactor — every successfully decoded ristretto element is in the prime-order
subgroup, so there are no small-subgroup or cofactor attacks to contend with.

**CDS composition.** The split constraint `c_0 + c_1 = c` is what prevents a prover
who knows neither discrete log from succeeding: to simulate both clauses the prover
must commit one clause's challenge `cFake` *before* seeing `c`, which forces
`cReal = c − cFake`. The prover cannot also pre-commit the other clause's `cReal`
because `c` is not yet known — so it can simulate at most one clause per transcript.
Two transcripts with distinct `c` therefore force the real clause to have
`cReal ≠ cReal'`, enabling extraction.

**Lifting to the range.** `verifySub` checks `Σ_i C_i · 2^i = C_target`. Per-bit
extraction certifies each `b_i ∈ {0, 1}` with known randomness `r_i`, so the
committed value `Σ_i b_i · 2^i` is a well-defined integer in `[0, 2^n)` — provided
no wraparound mod `L`. The `n ≤ 251` hard cap (ZKRANGE-002, see §4) ensures
`2^{n+1} ≤ L` so neither `amount` nor `diff = threshold − 1 − amount` can alias
across the group order. Applying this to both sub-proofs establishes
`0 ≤ amount < threshold` over the integers.

**Residual assumption.** This is a knowledge-soundness statement under discrete-log
hardness on ristretto255 and OR-simulation-soundness. It is classical and **UNAUDITED**.

---

### §2 — HVZK: the OR-Composition Simulator

**Claim.** Each per-bit OR-proof (`proveBit` / `verifyBit`) is HVZK. There exists a
simulator that, without the witness `(b_i, r_i)`, produces transcripts identically
distributed to honest prover transcripts (in ROM, by programming the challenge oracle).

**Argument.**

For a **full simulation** (no witness at all) of bit `i` with statement `C_i`:

1. Sample the overall bit challenge `c$ ← $ uniform in `{0,…,L−1}` (in Fiat–Shamir,
   this is the value the simulator **programs** the oracle to return on this input).
2. Sample `c_0 ←$ uniform`; set `c_1 = c − c_0  mod L`.
3. For each clause `j ∈ {0, 1}`: sample `s_j ←$ uniform`; set
   `t_j = H^{s_j} · P_j^{−c_j}`.

The simulated transcript `(t_0, t_1, c_0, c_1, s_0, s_1)` satisfies conditions (B)
and (C) by construction. The distribution argument:

- In an honest proof, the real clause `j = b_i` computes `s_j = k_j + c_j · r_i`
  with `k_j ←$ uniform`, so `s_j` is uniform; `t_j = H^{k_j}` is a uniform group
  element (since `k_j` is uniform and `H` generates the full prime-order group).
- In the simulation, `s_j ←$ uniform` and `t_j = H^{s_j} · P_j^{−c_j}` — for a
  fixed `c_j`, this is again a uniform group element (bijection from `s_j` to `t_j`).
- The challenge split `(c_0, c_1)$ with $c_0 + c_1 = c$ and $c_0$ uniform is
  distributed identically to the split in an honest execution.

Therefore the simulated transcript is identically distributed to an honest transcript.
Since `H^r` is **perfectly hiding** (Pedersen commitments are perfectly hiding for any
non-degenerate generator pair, regardless of the relationship between `G` and `H`),
the simulator never needs the opening `(b_i, r_i)`. The OR structure ensures the
verifier and any transcript observer cannot determine which clause was "real."

**Composition.** The full dual-range proof consists of `2n` OR-proofs (n bits for
`amount` and n bits for `diff`) plus public homomorphic checks. The per-bit simulators
compose: sequential ZK composition in the ROM is standard, and the bit commitments
`C_i` are themselves perfectly hiding. Therefore:

- **Amount confidentiality is information-theoretic / perfectly hiding.** No adversary,
  classical or quantum, recovers `amount` from a proof. There is no
  harvest-now-decrypt-later risk for the amount.
- **Soundness / binding is classical.** A future quantum adversary computing discrete
  logs could forge an in-range proof for an out-of-range amount. Receipt-envelope
  integrity remains PQ (ML-DSA-87); the ZK proof's integrity is classical.

**Residual assumption.** HVZK + Fiat–Shamir gives non-interactive ZK in the ROM; the
simulator programs the oracle. This is the standard model for sigma protocols and is
**UNAUDITED** here.

---

### §3 — Fiat–Shamir Transcript Completeness and the Joint-Challenge Requirement

This section contains the highest-severity finding from the PhD council review.

#### 3.1 The Incompatibility of Per-Bit Challenge Binding with Special-Soundness

**Claim (council finding).** Per-bit challenge binding — where each of the `2n` bits
draws its Fiat–Shamir challenge from an independent oracle call binding only that
bit's own first messages `(t^{(i)}_0, t^{(i)}_1)` — is **mathematically incompatible**
with Sigma-protocol special-soundness for the full `2n`-bit composite proof.

**Argument.**

Special-soundness for the composite is defined (Definition 2 above) over the full
witness `(b_0, …, b_{2n−1}, r_0, …, r_{2n−1})`. The extractor requires two accepting
transcripts that share **all** `2n` first-message vectors and differ in the overall
challenge. Under per-bit binding, "the overall challenge" does not exist as a single
object: there are `2n` independent scalar challenges `c^{(0)}, …, c^{(2n−1)}`, each
a function only of `stmt` and `(t^{(i)}_0, t^{(i)}_1)`.

For the extractor to work for bit `i`, it needs two transcripts where `c^{(i)}` differs
while `(t^{(i)}_0, t^{(i)}_1)` is shared. But `c^{(i)} = H(stmt, tag_i, C_i, P_0, P_1,
t^{(i)}_0, t^{(i)}_1)`: the challenge is a **deterministic function** of the first
messages. Two transcripts with the same `(t^{(i)}_0, t^{(i)}_1)` necessarily have
the **same** `c^{(i)}`. Therefore no pair of transcripts with the same per-bit first
messages can yield distinct per-bit challenges — the extractor's precondition can never
be satisfied.

More precisely: per-bit binding makes each bit proof a standalone non-interactive proof
for the Schnorr/Chaum–Pedersen relation, where the "challenge" is computed on the spot
from the announcement. The resulting system is **not a sigma protocol with a joint
challenge**; it is `2n` independent sigma protocols each with their own challenge. The
composition lacks a single joint challenge space from which two distinct transcripts
(sharing all announcements) could be drawn.

**Consequence.** Without a single joint challenge:

1. The extraction argument in §1 applies per-bit only in the **interactive** setting
   (where the verifier supplies a fresh random challenge). In the non-interactive
   (Fiat–Shamir) setting, per-bit binding provides **computational** binding via
   hash collision resistance, but does **not** support the algebraic extraction proof
   that underlies special-soundness.
2. The security reduction from the ZK proof to discrete-log hardness becomes
   non-standard and requires individual analysis per-bit, with no clean joint-witness
   extraction property.

#### 3.2 The Frozen Heart / Weak-FS Hazard

Fiat–Shamir is sound only if the challenge is a hash of **every** public value the
soundness argument quantifies over. For the composite proof, the soundness argument
quantifies simultaneously over all `2n` first-message pairs. A cheating prover who
can choose some first messages *after* seeing partial challenges can exploit the
independent oracle calls.

The `statementHash` function in `zkrange.ts` (v2, post-council review 2026-06-18)
already binds `(n, threshold, C_amt,` all `2n` bit commitments`)` into a shared
`stmt` digest included in every per-bit challenge. This closes the weakest form of
Frozen Heart (commitment re-use across bits). However, because the first messages
`(t^{(i)}_0, t^{(i)}_1)` of bit `j` are **not** in the challenge of bit `k ≠ j`, a
structurally adversarial prover could, in principle, choose first messages for later
bits after observing earlier per-bit challenges. The `statementHash` dependency on the
bit commitments (not the first messages) means bit commitments `C_i` are fixed before
any challenge, but the first messages remain per-bit free.

Additionally, neither `G` nor `H` are hashed into the transcript. Soundness relies on
`dlog_G(H)` being unknown for the fixed compile-time `H`. A future code path that
parameterised `H` (e.g. per-deployment generator) would silently reuse challenges
across different generators.

#### 3.3 Required Construction: Single Joint Fiat–Shamir Challenge

**Requirement.** Any conforming Nerion implementation of the dual-range OR-proof MUST
use a **single joint Fiat–Shamir challenge** derived from a single hash over the
**complete** transcript, as follows:

```
c* = SHAKE256(
       domain-separator         ‖
       G.toBytes()              ‖    -- generator G (explicit, not implicit)
       H.toBytes()              ‖    -- generator H (explicit, not implicit)
       n as uint16-BE           ‖    -- bit count
       threshold as uint256-BE  ‖    -- range bound
       C_amt.toBytes()          ‖    -- amount commitment
       C_i.toBytes()  ∀ i       ‖    -- all 2n bit commitments (both sub-proofs)
       t^{amount,(i)}_0.toBytes() ∀ i ‖  -- all amount-sub first messages
       t^{amount,(i)}_1.toBytes() ∀ i ‖
       t^{diff,(i)}_0.toBytes()  ∀ i ‖  -- all diff-sub first messages
       t^{diff,(i)}_1.toBytes()  ∀ i
     , dkLen=64 )
```

where `domain-separator = "Nerion/disclosure/stmt/v3"` (or the versioned tag agreed
in the implementing PR). Per-bit challenges are then derived deterministically from
this single root:

```
c^{(role, i)} = SHAKE256( c* ‖ "bit" ‖ role-byte ‖ i as uint16-BE , dkLen=64 )
              reduced mod L
```

with `role ∈ {0x00 = amount, 0x01 = diff}`.

**Why this construction satisfies special-soundness.** Given any two accepting
transcripts on the **same** full first-message vector `{(t^{(i)}_0, t^{(i)}_1)}_i`
with distinct root challenges `c* ≠ c*'`, at least one derived per-bit challenge
`c^{(role, i)} ≠ c^{(role, i)}'` (by collision resistance of SHAKE256). The
extractor for that bit proceeds as in §1. Because the root challenge is a function of
**all** first messages, two transcripts sharing all first messages will produce the
same root challenge (deterministic hash), so the only way to get `c* ≠ c*'` is for
the transcripts to differ in at least one first message — which forces the extraction
argument through the appropriate bit. This is the standard strong Fiat–Shamir
security theorem for multi-clause sigma protocols.

**Prover ordering.** The commit-then-challenge discipline is enforced: the prover MUST
compute all `2n` first-message pairs `(t^{(i)}_0, t^{(i)}_1)` for both sub-proofs
before computing any challenge. This is the standard two-pass structure for
multi-clause non-interactive proofs.

**OR composition validity.** For each bit `i`, the per-bit challenge
`c^{(role,i)}` is still derived deterministically and is shared between `proveBit`
and `verifyBit`. The CDS split `c^{(role,i)}_0 + c^{(role,i)}_1 = c^{(role,i)}`
continues to hold; only the derivation of the per-bit challenge root changes. The
per-bit OR-proof argument (§1) is fully preserved under this rederivation.

**Is a single joint challenge sufficient for the OR composition?** Yes. OR-composition
(CDS) does not require independent per-clause challenges; it requires only a single
challenge `c` per bit which is split into `(c_0, c_1)` with `c_0 + c_1 = c`. The
single-scalar Fiat–Shamir challenge provides exactly this. The "per-bit" level of
the proof is a single sigma protocol (the 2-clause OR), not a sequential composition,
so the joint root challenge `c*` feeding per-bit scalars `c^{(role,i)}` is the
correct construction for the multi-bit sequential composition.

---

### §4 — The `n ≤ 251` Integer-Range / No-Wraparound Argument

Special-soundness establishes `Σ_i b_i · 2^i` is in `[0, 2^n)` **as an integer**
only if the recomposition does not wrap modulo `L`. Two documented failure modes:

- **ZKRANGE-001.** If `n` were large enough that `2^n ≥ L`, the committed value could
  wrap the group order, so a false claim "`< threshold`" could be satisfied by a
  mod-`L` alias. Closed by capping `n` and by the `proof.n === n` check (the verifier
  ignores the proof's `n` field and uses its own protocol constant).
- **ZKRANGE-002 (off-by-one, found by Team Apex 2026-06-21).** `L = 2^252 + d` with
  `d ≈ 2^124.7`. At `n = 252`, a negative `diff` wraps to `L − |diff| ∈ [0, 2^252)`,
  so a huge `amount ≈ 2^124` could falsely prove `< threshold`. The cap `n ≤ 251`
  (equivalently, `2^{n+1} ≤ L`) closes it, because for `n ≤ 251`:
  - `amount ≤ 2^n − 1 < 2^251`
  - `diff = threshold − 1 − amount ≤ 2^n − 1 < 2^251`
  - Both are well below `L/2 < 2^252`, so no positive value in `[0, 2^n)` can be
    confused with a wrapped negative.

Both `proveBelow` and `verifyBelow` enforce `n ∈ [1, 251]`; `proveBelow` refuses to
emit a proof at an unsound bit-length rather than produce one the verifier will reject.
This integer-range argument is a **priority audit item** — one off-by-one has already
been found and corrected.

---

## Implementation Plan (design only; no code in this ADR)

If the external ZK/crypto audit ratifies the joint-challenge construction in §3.3:

1. **New statement version.** Introduce `Nerion/disclosure/stmt/v3` domain tag.
   The current `v2` per-bit path (`PolarSeek/disclosure/stmt/v2`) is unchanged and
   remains the default until the audit signs off. No silent behaviour change; `v2`
   proofs keep verifying under the `v2` verifier.
2. **`statementHash` v3.** Restructured to accept all `2n` first-message vectors as
   additional inputs, produce the single root challenge `c*`, and bind `G.toBytes()`
   and `H.toBytes()` explicitly (closing the generator-binding gap noted in §3.2).
3. **Two-pass prover.** Under v3, `proveBelow` computes all `2n` pairs
   `(t^{(i)}_0, t^{(i)}_1)` first (commit phase), then calls `statementHash` v3 to
   derive `c*`, then derives per-bit `c^{(role,i)}` and runs the response phase. The
   dual-range structure, the `n ≤ 251` cap, the homomorphic checks, and Pedersen
   commitments are unchanged.
4. **KAT vectors.** The `v2` KAT vectors are untouched (different domain tag ⇒ different
   bytes). A new `v3` vector set is added. Cross-version non-malleability is tested:
   a `v2` proof MUST NOT verify under a `v3` verifier and vice-versa.
5. **Gating.** Nothing merges to the default path until the external audit reviews the
   argument in this ADR and the v3 transcript.

---

## Audit Items

The following items are explicitly flagged for the external ZK/crypto audit:

1. **Per-bit vs. joint challenge (§3).** Confirm that the single joint Fiat–Shamir
   challenge construction (§3.3) achieves special-soundness for the `2n`-bit
   composition, or provide a counter-argument and alternative.
2. **OR composition challenge sufficiency (§3.3).** Confirm that a single per-bit
   scalar `c^{(role,i)}` (derived from `c*`) is sufficient for CDS OR composition,
   i.e. that no additional independence between bits is required.
3. **`n ≤ 251` bound (§4).** Verify the no-wraparound argument; in particular, confirm
   the `+1` margin (`2^{n+1} ≤ L`) is tight and that no off-by-one remains.
4. **Generator binding (§3.2).** Confirm that binding `G` and `H` explicitly into
   the transcript (v3) is necessary and sufficient to prevent generator-substitution
   attacks.
5. **FS transcript completeness (§3.2 + §3.3).** Verify the v3 transcript includes
   the full statement per the Frozen Heart checklist: all commitments, all first
   messages, all generators, domain separator, and protocol version.
6. **HVZK composition (§2).** Confirm the sequential composition of `2n` HVZK
   simulators is standard in the ROM; no additional argument needed.
7. **Integer-range / dual-range joint soundness (§1 + §4).** Confirm that per-bit
   extraction plus `verifySub` homomorphic recomposition plus `C_diff` verifier
   reconstruction establishes `0 ≤ amount < threshold` as an integer, without
   further conditions.

---

## Alternatives Considered

1. **Leave per-bit binding as-is with documentation only.** The `stmt` shared across
   all per-bit hashes provides joint binding on the bit *commitments*, which is the
   most common Frozen Heart fix cited for sigma protocols. However, the PhD council
   review establishes this does not recover the algebraic joint-extraction property of
   a single joint challenge for the `2n`-bit composition. Documentation alone is
   insufficient — the incompatibility with special-soundness must be resolved.
   **Rejected as the sole option.**

2. **Switch to Bulletproofs / inner-product arguments.** Logarithmic proof size, but
   a new primitive requiring its own audit. Does not change the soundness *argument*
   this ADR is asked to record. Out of scope.

3. **Prove `b_i(b_i − 1) = 0` algebraically instead of OR-proof.** Equivalent
   soundness goal (proves each `C_i` commits to a bit), but changes the construction
   wholesale and discards the reviewed CDS structure. Rejected for this ADR.

4. **Bind only the generators without single-transcript binding.** A partial
   improvement addressing gap (c)(1) from ADR-0016 / the earlier ADR-0017 draft. The
   PhD council finding establishes the joint-challenge issue as the more
   structurally significant problem; a generator-only fix would leave it unresolved.
   Recorded as insufficient.

---

## Consequences

### Positive

- The transcript soundness argument is formally recorded, enabling the external audit
  to verify or refute it against the implementation.
- The joint-challenge requirement (§3.3) gives auditors a clean special-soundness
  extraction proof for the full `2n`-bit composition.
- Explicit generator binding closes the transcript self-description gap; the proof
  becomes independent of compile-time constants.
- Any implementation MUST produce transcripts matching the joint-challenge
  specification; this is now a conformance requirement (see Audit Items above).

### Honest Caveats

- **UNAUDITED.** This is a ROM (classical) argument, not a proof and not a QROM
  result. It is a prerequisite *input* to the external ZK/crypto audit, alongside
  ADR-0006 and ADR-0013.
- **No production privacy or soundness claim.** Nothing here is "audited,"
  "production-ready," FIPS-validated, or a non-infringement statement.
- **No code change in this ADR.** No vector, test, or behaviour changes. The `2n`-bit
  composition continues to use the existing `v2` per-bit binding until the audit
  ratifies the v3 joint-challenge construction and an implementing PR is reviewed.

### QROM Residual Risk

The Fiat–Shamir transform's soundness in the **quantum random-oracle model (QROM)**
is a separate, stronger question that this ADR does **not** address.

In the classical ROM, soundness follows from the standard Fiat–Shamir theorem:
a quantum-polynomial-time adversary that makes at most `q` oracle queries can break
soundness with probability at most `O(q / 2^κ)` plus the underlying discrete-log
hardness (where `κ` is the challenge bit length, here `≈ 512` bits from the 64-byte
SHAKE256 output, so the `q / 2^κ` term is negligible).

In the **QROM**, the adversary can make superposition (quantum) queries to the random
oracle. For standard Sigma protocols transformed by Fiat–Shamir, QROM soundness
requires additional care:

1. **Superposition-query rewinding.** The classical "rewinding" argument (run the
   adversary twice on the same first message with different challenges) does not
   directly apply when the adversary makes superposition queries. QROM security of
   Fiat–Shamir for *arbitrary* sigma protocols requires additional properties
   (e.g. "collapsing" of the hash function, or a direct QROM reduction for the
   specific protocol).
2. **Binding is already classical.** The Pedersen commitment's binding property rests
   on discrete-log hardness — already broken by a quantum adversary running Shor's
   algorithm. The ZK proof's soundness is therefore **already not post-quantum** at the
   binding layer, independently of the QROM question.
3. **Amount confidentiality is unconditional.** Pedersen is perfectly hiding; a quantum
   adversary cannot recover `amount` from the proof transcript regardless of computing
   power. There is **no harvest-now-decrypt-later risk** for the amount.

**Summary of the QROM residual risk.** The dual-range OR-proof provides:
- Amount **confidentiality**: information-theoretic, unconditional, PQ-safe.
- Proof **soundness** (binding): classical discrete-log hardness. Not QROM-analyzed.
  A quantum adversary that solves discrete log on ristretto255 could forge an
  in-range proof for an out-of-range amount. The receipt-envelope integrity (ML-DSA-87)
  is PQ; the ZK proof's integrity is classical.

This QROM gap is a **documented residual risk**. The Nerion protocol's overall
security posture does not depend on ZK-proof soundness being PQ — the governance
layer (Nerion kernel, quorum receipts, ML-DSA-87 envelope) provides PQ integrity for
the receipt itself; the ZK proof provides *additional* privacy without degrading PQ
receipt integrity.

### Binding List of Residual Assumptions

All of the following must hold for the ROM soundness argument in this ADR:

- (i) Discrete-log hardness on ristretto255 (classical; broken by a quantum adversary).
- (ii) OR-simulation-soundness: the CDS composition is simulation-sound (standard
  classical assumption).
- (iii) SHAKE256 is a random oracle in the classical ROM (not the QROM).
- (iv) `dlog_G(H)` is unknown for the fixed NUMS generator `H` (ADR-0016); the
  commitment is computationally binding under this assumption.
- (v) The `n ≤ 251` no-wraparound bound is tight (priority audit item §4).
- (vi) The verifier reconstructs `C_diff = (threshold − 1)·G − C_amt` from public
  data and does not accept a prover-supplied `C_diff`. This is the load-bearing
  structural condition that prevents the adversary from choosing the `diff` sub-proof
  target.
- (vii) The single joint challenge construction (§3.3) is implemented exactly in the
  v3 prover and verifier — any deviation breaks the extraction argument.

---

## References

- `disclosure/src/zkrange.ts` — the construction argued here: `commit`, `proveBit`,
  `verifyBit`, `buildBits`, `proveSub`, `verifySub`, `statementHash`, `challenge`,
  `proveBelow`, `verifyBelow`, ZKRANGE-001 / ZKRANGE-002.
- `disclosure/test/zkrange.test.ts`, `disclosure/test/zkrange.property.test.ts`,
  `disclosure/test/zkrange-adversarial.test.ts` — existing tests.
- `conformance/src/suite.ts` — C11 (range proof) and C13 (policy-satisfaction proof)
  sit atop this OR-proof.
- ADR-0006 — Zero-Knowledge Policy-Satisfaction Receipts (consumes the dual range proof;
  UNAUDITED composition; PQ profile note).
- ADR-0013 — v:2 commitment-to-intent equality (public-input binding caveat mirrors
  the generator-binding gap §3.2 of this ADR).
- ADR-0016 — Pin the Pedersen generator `H` provenance + fail-closed startup
  invariants (NUMS construction for `H`; binding assumption root).
- `docs/STATUS.md` — UNAUDITED-protocol status tracking.
- Cramer, Damgård, Schoenmakers — "Proofs of Partial Knowledge and Simplified Design
  of Witness Hiding Protocols" (CRYPTO 1994) — the CDS OR-composition this argument
  follows.
- Fiat, Shamir — "How To Prove Yourself: Practical Solutions to Identification and
  Signature Problems" (CRYPTO 1986) — the non-interactive transform.
- Don, Fehr, Majenz, Schaffner — "Security of the Fiat-Shamir Transformation in the
  Quantum Random-Oracle Model" (CRYPTO 2019) — the QROM gap documented in §QROM above.
- Chalkias, Garillot, Nikolaenko — "Taming the many EdDSAs" (SSR 2020) — ristretto255
  prime-order group and cofactor arguments.
- The "Frozen Heart" vulnerability class — Buterin, Drake, Boneh, "Why and How zk-SNARK
  Keys Are Sacrificial" and the Dalek-ng audit (2022) — the weak-FS checklist §3.2
  applies.
