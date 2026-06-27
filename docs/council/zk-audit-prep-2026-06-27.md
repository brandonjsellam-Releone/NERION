<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nerion ZK disclosure layer — external-audit preparation dossier

**Date:** 2026-06-27 · **Status:** internal review artifact · **Branch:** `apex/team-review-integration`

> **What this is.** An _audit-preparation_ document for the bespoke zero-knowledge
> disclosure layer (`disclosure/src/`). It is the product of an **internal**
> close-reading (main-loop review; the multi-model council seats were server-rate-limited
> during this run and did not contribute — this is therefore a single-reviewer pass, not a
> council consensus). Its sole purpose is to make the **funded external ZK audit**
> (NLnet-scoped, OSTIF / OTF threads) _efficient_: it scopes the questions the auditor
> must answer and records a few concrete hardening candidates. **It is NOT an audit, NOT a
> proof, and NOT a security claim.**
>
> **Re-affirmed status of the layer (unchanged):** the **group** (ristretto255) and **hash**
> (SHAKE256) are externally audited via `@noble`; the **protocol composition** is **UNAUDITED**.
> Soundness/binding rest on a **classical** discrete-log assumption (**not post-quantum**).
> Zero-knowledge is argued in the **classical random-oracle model**, **not the QROM**. See
> [`docs/STATUS.md`](../STATUS.md), [`docs/ASSURANCE.md`](../ASSURANCE.md), `ADR-0006/0013/0014`.

---

## 1. Scope

| File                            | Construction                                                                                                                                                                                             | Lines of interest                                                                                                       |
| ------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `disclosure/src/zkrange.ts`     | Pedersen commit `C = G^v·H^r` over ristretto255; bit-decomposition range proof; Chaum–Pedersen/CDS OR-proof per bit; dual-range (`amount` **and** `diff = thr−1−amount`); strong Fiat–Shamir (SHAKE256). | `commit` 70, `proveBit` 135, `verifyBit` 154, `verifySub` 201, `proveBelow` 220, `verifyBelow` 258, `statementHash` 104 |
| `disclosure/src/policyproof.ts` | Policy-satisfaction proof: composes two range proofs — `amount ≤ ceiling` and `amount + aggregate ≤ cap` over the homomorphic sum commitment. Binding digest `policyProofDigest`.                        | `provePolicySatisfaction` 101, `verifyPolicySatisfaction` 123, `policyProofDigest` 169                                  |
| `disclosure/src/commitbind.ts`  | v:2 structural commitment-binding (ADR-0013): digest over `{domain, intent-skeleton (amount omitted), commitment}`; point-binding vs full (opening) check.                                               | `intentAmount` 66, `boundIntentDigest` 91, `verifyBoundAmount` 125, `bindAmountCommitment` 150                          |
| `disclosure/src/selective.ts`   | Salted hash commitment (RCPT-001/ADR-0014) for hiding low-entropy receipt fields.                                                                                                                        | `commitField` 40, `verifyDisclosure` 51                                                                                 |

**Group facts the audit must take as given.** ristretto255 prime-order group, order
`L = 2^252 + δ`, `δ ≈ 2^124.6`; no cofactor / no small-subgroup points (ristretto encoding).
`G = base`; `H = hashToCurve("PolarSeek/disclosure/generator-H/v1")` (nothing-up-my-sleeve).

---

## 2. Audit checklist — what the external ZK auditor must confirm

Each item is a **question**, not an assertion of a defect. `[CONFIRM]` = expected to hold,
auditor verifies; `[ITEM]` = a genuine open question or hardening candidate this review raised.

### P1 — Special-soundness / knowledge extraction

- **[CONFIRM]** The per-bit CDS OR-proof (`proveBit`/`verifyBit`, `zkrange.ts:135/154`) is
  2-special-sound: two accepting transcripts sharing `(t0,t1)` with distinct global challenge
  `c` extract `r_i` and the bit. Verifier enforces `mod(c0+c1) === c` (`:158`) and both
  Schnorr checks on base `H` (`:160-161`). Confirm the extractor and the exact soundness bound.
- **[CONFIRM]** The OR genuinely forces the `G`-exponent of `C_i` into `{0,1}` as integers
  (membership in `{H^r} ∪ {G·H^r}` ⇒ exponent `≡ 0` or `1 mod L`), so `Σ b_i 2^i` is a true
  `n`-bit integer.
- **[CONFIRM]** Aggregation soundness: `verifySub` checks `Σ C_i·2^i == target` (`:204-205`)
  in the group; with the `n ≤ 251` cap (`2^{n+1} ≤ L`) the sum cannot wrap mod `L`, so the
  group equality implies the integer equality `value = Σ b_i 2^i ∈ [0,2^n)`. **This is the
  ZKRANGE-002 fix** (`verifyBelow:258-259`, prove side `:223`) — confirm the cap is the
  tight bound and that _both_ sub-proofs (amount, diff) enforce it.
- **[ITEM]** There is **no written soundness theorem / extractor** — the argument lives in
  code comments. The auditor should produce or confirm the formal extractor and the dual-range
  → `0 ≤ amount < threshold` reduction (`zkrange.ts:17-24`).
  _Operationalized:_ a written **argument sketch** (extractor construction, aggregation/binding
  step, dual-range disjointness, strong-FS) is now provided for the auditor to verify or refute:
  [`docs/formal/zk-range-soundness-argument.md`](../formal/zk-range-soundness-argument.md). It is
  a sketch in the classical ROM — **not** a machine-checked proof and **not** a tight
  knowledge-error bound; §6 there lists exactly what the audit must still establish.

### P2 — Honest-verifier zero-knowledge (simulation)

- **[CONFIRM]** CDS simulator: real branch is a true Schnorr (`t=H^k`, `s=k+c·r`); fake branch
  samples `(s,c)` and back-computes `t=H^s·P^{-c}` (`proveBit:138-148`). In the ROM the
  simulator programs the SHAKE256 oracle. Confirm transcripts are perfectly/statistically
  simulatable.
- **[CONFIRM]** Challenge/response uniformity: `randScalar` draws **64 bytes** reduced mod `L`
  (`:53-54`), so the modular bias is `≤ 2^{-260}` (negligible). Confirm no biased sampling path.
- **[ITEM]** **Prover nonce quality is load-bearing.** `kReal = randScalar()` (`:138`) feeds a
  Schnorr response; a repeated or low-entropy nonce leaks the witness (ECDSA-class failure).
  Confirm `randomBytes` is a CSPRNG with **no derandomized / deterministic-nonce path**, and
  that nonces are never reused across proofs. _Operationalized (partial):_
  `disclosure/test/zkrange-nonce-freshness.test.ts` pins that proving is non-deterministic (two
  proofs of the same statement/witness differ, both verify), ruling out an accidentally
  derandomized prover. It cannot prove `randomBytes` is a CSPRNG — that remains for the auditor.
- **[ITEM / KNOWN]** ZK is argued in the **classical ROM only**; **QROM is unanalyzed**
  (`policyproof.ts:37-40`). Auditor to either supply a QROM argument or bound the classical-ROM
  claim and state the residual.

### P3 — Fiat–Shamir transcript binding (Frozen-Heart class)

- **[CONFIRM]** `statementHash` (`:104-113`) absorbs the domain tag **with `n` and `threshold`**,
  the amount commitment `cAmt`, **all** amount bit-commitments, and **all** diff bit-commitments
  — before any per-bit challenge is drawn (`proveBelow:235` precedes `proveSub`). Each per-bit
  challenge additionally binds `ci,P0,P1,t0,t1` under an **index- and sub-proof-scoped tag**
  `bit/${prefix}/${i}` (`:196,208`), preventing bit-index / cross-sub-proof splicing. Confirm
  this is the full statement and closes weak-FS / Frozen-Heart.
- **[ITEM]** Generators `G,H` are **not** absorbed into the transcript. Defensible (they are
  frozen protocol constants), but the auditor should confirm there is no parameter-substitution
  attack and consider absorbing them for domain rigor.

### P4 — Generator / parameter provenance

- **[CONFIRM]** `H` is derived by `hashToCurve` of a fixed domain string (`zkrange.ts:37`), so
  `dlog_G(H)` is unknown (binding ⇄ hiding separation holds). Confirm reproducibility.
  _Operationalized:_ both generators are now pinned by a regression test
  (`disclosure/test/zkrange-generators.test.ts`) via the public `commit` API
  (`commit(1,0)=G`, `commit(0,1)=H`), so any silent move of `H` — from an `@noble` change
  or a domain-string edit (e.g. the PolarSeek→Nerion rename) — fails CI as a conscious change.
  Pinned `H = c0ec2340…b759a546`, `G = e2f2ae0a…08d2d76`.
- **[ITEM]** Confirm `ristretto255_hasher.hashToCurve` is the **uniform/indifferentiable hash**
  variant (RFC 9380 _hash_-to-curve), **not** a non-uniform _encode_-to-curve, so `H` is a
  genuine random group element.

### P5 — Policy-satisfaction composition

- **[CONFIRM]** Both sub-proofs are over the **same** committed amount: `ceiling` over `C`, and
  `aggregate` over `C_sum = C + G^{aggregate}` reconstructed by the verifier via
  `shiftCommitment` (`policyproof.ts:139`). The prover cannot use two different amounts.
- **[CONFIRM]** Fail-closed wiring: capped policy with no aggregate ⇒ reject (`:133`); stray
  aggregate proof under an uncapped policy ⇒ reject (`:141-143`); `n` mismatch ⇒ reject
  (`:129`).
- **[ITEM / LINKAGE]** `bounds.aggregate` is a **public, externally-signed scalar the ZK layer
  trusts as input** — the proof does **not** prove the running total is correct
  (`policyproof.ts:42-49`, `commitbind.ts` trust model). End-to-end soundness depends on the
  authenticity of whatever supplies the aggregate and on binding `commitments.psr` into the
  signed receipt. Auditor must trace this wiring.
- **[ITEM]** **Parameterization cliff.** `proveBelow` requires `amount + aggregate < 2^n`
  (`zkrange.ts:226`), else it throws. With the default `n=32` the sum must be `< 2^32`. Not
  unsound (fail-closed), but `n` must be chosen for the application's value range or honest
  provers fail. Confirm the deployed `n`.

### P6 — Commitment binding & hiding

- **[CONFIRM]** Pedersen binding is computational (DL); hiding is **perfect** — the hidden
  amount has no harvest-now-decrypt-later exposure (`policyproof.ts:28-35`). Salted commitments
  (`selective.ts:40-44`) are binding+hiding when the salt is high-entropy and off-leaf.
- **[CONFIRM]** CB-001 fix: `boundIntentDigest` **omits `amount`** from the public pre-image
  (`commitbind.ts:91-101`); `verifyBoundAmount` re-checks `commit(intentAmount, opening)==C`
  when the opening is available (`:125-134`). The public digest does not make the amount
  brute-forceable.
- **[ITEM — raised here, PRESENT not hypothetical]** **Denylist, not allowlist.** The skeleton
  is built by _excluding only_ the field named `amount` (`commitbind.ts:94`,
  `filter(([k]) => k !== 'amount')`). Every **other** `ActionIntent` field is therefore hashed
  into the public, externally-recomputable digest — **including `counterparty`** (typed in
  `capabilities/src/types.ts:26-27` as an opaque reference _"never re-identified across calls"_,
  i.e. privacy-sensitive) **and arbitrary `params`** (`:30-31`). If `counterparty` or any
  `params` value is **low-entropy / enumerable**, it is brute-forceable from a _single_ public
  digest exactly as the amount was pre-CB-001: the commitment is public, the rest of the skeleton
  is public, so a holder enumerates the candidate and matches the hash. (The random Pedersen
  commitment blinds _cross-call linkage_ of a repeated counterparty, but **not** single-receipt
  _recovery_ of an enumerable value.) This is a **present** exposure, not only a future-schema
  hazard. Recommended: invert to an **allowlist** of known-public fields — but note the inverse
  risk (an allowlist that drops a legitimately-public field weakens binding-completeness), so this
  is a design decision for an ADR + council, not a unilateral flip. A regression test now **locks
  the excluded-field set** (`disclosure/test/commitbind-cb001-surface.test.ts`) so any change is
  conscious.
- **[ITEM — raised here]** **Salt is a caller responsibility not enforced here.** `selective.ts`
  neither generates the salt nor guarantees it is excluded from the signed body/log leaf — both
  are asserted in prose (`:18-22`) but enforced at call sites. Auditor must confirm at every
  integration point that (a) the salt has ≥128-bit entropy and (b) it never reaches the public
  artifact.
- **[ITEM / KNOWN]** Structural binding does **not** defend against a malicious binder/kernel at
  admission (`commitbind.ts:30-32`) — that is the quorum/attestation model's job. Confirm the
  threat model treats the admission binder as trusted.

### Cross-cutting

- **[ITEM — raised here] Domain-prefix inconsistency.** `selective.ts` uses `"Nerion/disclosure/
salted-commit/v1"` (`:28`) while `zkrange.ts` (`:37,105`), `commitbind.ts` (`:51`) and
  `policyproof.ts` (`:175`) still use the legacy `"PolarSeek/..."` prefix. Cosmetic for
  _soundness_, but it is a **domain-separation / migration hazard**: these strings are
  protocol-frozen (they feed `H`, the FS transcript, and every digest), so the PolarSeek→Nerion
  rename is a **breaking change requiring a protocol-version bump + fresh KATs**, not a
  find-and-replace. Reconcile before the rename lands.
- **[ITEM] Decode boundary is the malleability/DoS surface.** The `verify*` functions here take
  already-parsed `Pt`/`bigint`. Confirm the wire→object decode path (outside these files)
  strictly validates point encodings and rejects non-canonical scalars (`c0,c1,s0,s1,opening < L`)
  before these functions run. _Operationalized:_ `disclosure/test/decode-boundary.test.ts` pins
  that the verifier is **mod-invariant** — a proof carrying a non-canonical scalar (`s + L`)
  verifies identically — so canonicality rejection is genuinely the decode boundary's job, and
  also exercises the fail-closed paths (over-cap `n`, malformed sub-proof: reject, never throw).
- **[ITEM] Proofs are not unique (re-randomizable).** Schnorr/CDS proofs are malleable; this is
  contained because `policyProofDigest` binds the serialized proof into the ML-DSA-87-signed
  receipt body (`policyproof.ts:169-191`). Confirm a malleated proof cannot be substituted under
  the same signature. _Operationalized:_ the same test demonstrates the containment directly — a
  scalar-malleated proof still `verify`s `true` **but** yields a **different** `policyProofDigest`,
  so a signed receipt rejects the byte-level malleation.
- **[ITEM] Prover-side timing.** JS `bigint` arithmetic and the bit extraction
  `(value >> i) & 1n` (`zkrange.ts:183`) are not constant-time; scalar-mult is constant-time via
  `@noble`. Verify-side has no secret. Auditor to assess prover-side side-channel exposure
  against the deployment's threat model (server-side proving ⇒ lower risk).

---

## 3. Properties this review argues already hold (auditor to confirm)

1. **Dual-range soundness with the `n ≤ 251` cap** — no wrap mod `L`; ZKRANGE-001/002 closed.
2. **Strong Fiat–Shamir** — full statement (n, threshold, all commitments) fixed before any
   challenge; per-bit index/sub-proof domain separation.
3. **Perfect hiding of the amount** — information-theoretic; no PQ harvest risk to secrecy.
4. **CB-001 / RCPT-001 closed** — public digests/commitments omit or salt the secret amount.
5. **Fail-closed policy verification** — every misconfiguration path returns `false`.
6. **Nothing-up-my-sleeve `H`** — unknown `dlog_G(H)`.
7. **Negligible sampling bias** — 512→252-bit reduction for all scalars.

## 4. Known and accepted (re-affirmed, not new findings)

- Classical (discrete-log) soundness — **not** post-quantum; a quantum adversary could **forge**
  a satisfaction proof (it cannot recover the hidden amount).
- ZK argued in classical ROM; **QROM unanalyzed**.
- The protocol composition is **UNAUDITED**; group + hash are audited (`@noble`).
- Linkage contract: a proof attests _the committed_ amount; callers must bind the _decided_
  amount (ADR-0013 wiring is a scoped follow-up).
- Set-membership clauses (action-type / counterparty) are **deferred** (`policyproof.ts:18-20`).

## 5. What this dossier is **not**

It does not certify soundness, does not constitute the external audit, and raises **no claim of
a break**. The `[ITEM]`s in §2 are the questions and hardening candidates that should make the
funded ZK audit faster and cheaper — they are scope, not verdicts. The two concrete
recommendations a maintainer can act on now without an auditor are: **(a)** invert the
`boundIntentDigest` skeleton to an allowlist (P6); **(b)** reconcile the `PolarSeek`/`Nerion`
domain-prefix split as part of a versioned protocol migration (Cross-cutting).
