<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0017 — Soundness argument for the dual-range Chaum–Pedersen OR-proof (`disclosure/zkrange.ts`)

**Status: PROPOSED — design only, unimplemented (no code/KAT/behavior change in this ADR).**
This ADR records the *security argument* the current `disclosure/zkrange.ts` construction relies on, and a
proposed *tightening* of the Fiat–Shamir transcript binding. It is a **design decision record, not a security
result**. The argument below is **ROM (classical, random-oracle-model) special-soundness + HVZK reasoning**;
it is **NOT a QROM result**, and it is **UNAUDITED** — to be confirmed (or refuted) by the external ZK/crypto
audit. No production privacy or soundness claim is made here. Routes to: external ZK/crypto audit (the same
audit gating ADR-0006 and ADR-0013).

Date: 2026-06-21. Author: Track-B (Team Apex). Underlies conformance checks **C11** (range proof) and **C13**
(policy-satisfaction proof, ADR-0006), both of which sit on top of the per-bit OR-proof argued here.

## Context

`disclosure/zkrange.ts` proves, in zero knowledge, that a Pedersen commitment `C = G^amount · H^r` on the
audited prime-order ristretto255 group hides a value with `0 ≤ amount < threshold`, **without revealing the
amount**. The construction (per the file header and ADR-0006) is:

- a **dual** range proof — it proves BOTH `amount ∈ [0, 2^n)` AND `diff = (threshold − 1 − amount) ∈ [0, 2^n)`,
  which over the integers yields `0 ≤ amount < threshold` for `threshold ≤ 2^n`. (Proving only `diff` was the
  earlier, *unsound* version: an adversary could commit an out-of-range / mod-`L` value and pass.)
- each range is proven by **bit-decomposition**: the value is committed bit-by-bit as `C_i = G^{b_i} · H^{r_i}`
  with the weighted-randomness construction (`buildBits`) so that `Σ_i C_i·2^i = C` (checked in `verifySub`);
- each bit `b_i ∈ {0,1}` is proven by a **2-clause Chaum–Pedersen / CDS OR-proof** (`proveBit` / `verifyBit`):
  the prover shows it knows `dlog_H(P_0)` OR `dlog_H(P_1)`, where `P_0 = C_i` (so `C_i = H^{r_i}`, i.e. `b_i=0`)
  and `P_1 = C_i − G` (so `C_i − G = H^{r_i}`, i.e. `b_i=1`). The OR composition is the standard CDS trick: the
  prover simulates the false clause (picks `s_fake, c_fake`, back-solves `t_fake`) and runs the real clause
  honestly, with the constraint `c_0 + c_1 = c` where `c` is the Fiat–Shamir challenge.

The whole protocol is made **non-interactive via Fiat–Shamir**. The file (post council review 2026-06-18) binds
the **full statement** into a `statementHash` — `(n, threshold, C_amt, all amount-bit commitments, all
diff-bit commitments)` — which is mixed into every per-bit challenge, explicitly to close the weak-Fiat–Shamir
("Frozen Heart") class.

This ADR exists because that security argument has, to date, only been asserted in code comments and confirmed
informally by the multi-model council (ADR-0006). Track-B's job is to write it down rigorously and honestly,
flag the residual assumptions, and **propose a transcript-binding tightening** for the audit to rule on — not
to assert the construction is proven.

## Decision

1. **Record** the special-soundness, HVZK, and Fiat–Shamir-completeness argument for the dual-range OR-proof as
   the *claimed* security basis of `disclosure/zkrange.ts`, with every residual assumption marked.
2. **Propose (for the audit to ratify before any implementation)** a Fiat–Shamir tightening: replace the
   current *per-bit* challenge binding — where each bit's challenge re-hashes the shared `statementHash` plus
   that bit's own `(C_i, P_0, P_1, t_0, t_1)` — with a **single transcript challenge that binds ALL bit
   first-messages of both sub-proofs at once**, derived from one hash over the entire transcript, with per-bit
   challenges then derived deterministically from that single root (domain-separated). See "Soundness/Security
   argument · (c)". This is a **design proposal only**; it is NOT implemented here and would be gated behind the
   audit and a flag (see Implementation plan).
3. **Do NOT change any code, KAT vector, or behavior in this ADR.** The deliverable is this file alone.

## Soundness / Security argument (ROM, classical — UNAUDITED)

> Convention: `L` is the prime ristretto255 group order; `G`, `H` are generators with `H` a
> nothing-up-my-sleeve hash-to-curve point whose `dlog_G(H)` is unknown (binding rests on that). All scalar
> arithmetic is mod `L`. "ROM" = random-oracle model with SHAKE256 modelled as a random oracle.

### (a) Special-soundness of the per-bit OR-proof — witness extraction

*Claim.* The single-bit OR-proof (`proveBit`/`verifyBit`) is **2-special-sound**: from two accepting
transcripts that share the same first message `(t_0, t_1)` but have **distinct overall challenges** `c ≠ c'`,
an extractor recovers a witness — either `dlog_H(C_i)` (proving `b_i = 0`) or `dlog_H(C_i − G)` (proving
`b_i = 1`) — hence `C_i` opens to a genuine bit.

*Argument.* The verifier accepts iff (i) `c_0 + c_1 = c` (challenge split), and (ii) both Schnorr-style checks
hold: `H^{s_0} = t_0 · P_0^{c_0}` and `H^{s_1} = t_1 · P_1^{c_1}`, with `P_0 = C_i`, `P_1 = C_i − G`.

Take two accepting transcripts on the *same* `(t_0, t_1)`:
`(c_0, c_1, s_0, s_1)` with split `c = c_0 + c_1`, and `(c_0', c_1', s_0', s_1')` with split `c' = c_0' + c_1'`.
Since `c ≠ c'` and `c_0 + c_1 = c`, `c_0' + c_1' = c'`, at least one clause has a differing challenge: WLOG
`c_0 ≠ c_0'` (the `c_1` case is symmetric). Both transcripts satisfy the clause-0 check on the same `t_0`:

```
H^{s_0}  = t_0 · P_0^{c_0}
H^{s_0'} = t_0 · P_0^{c_0'}
```

Dividing, `H^{s_0 − s_0'} = P_0^{c_0 − c_0'}`. Because `L` is prime and `c_0 − c_0' ≠ 0 (mod L)`, it is
invertible, so the extractor outputs `dlog_H(P_0) = (s_0 − s_0') · (c_0 − c_0')^{-1} mod L`. That is exactly the
`H`-exponent of `C_i`, i.e. `C_i = H^{w}` with `w` known ⟹ `b_i = 0`. Symmetrically a differing `c_1` yields
`dlog_H(C_i − G)` ⟹ `b_i = 1`. In either case the extracted witness certifies `b_i ∈ {0, 1}`. ∎(claim)

*Why this needs the prime-order group.* Invertibility of `c_0 − c_0'` is what makes extraction work; it holds
because ristretto255 has prime order `L` (no cofactor, no small subgroup). The CDS OR-composition guarantees
that **at most one** clause can be simulated by a cheating prover: the simulator fixes one clause's challenge
*before* seeing `c`, so to satisfy `c_0 + c_1 = c` the *other* clause's challenge is forced and cannot also be
pre-committed — hence a prover who does not know either discrete log can satisfy at most one accepting transcript
per first message, and two with distinct `c` would extract a real witness it does not have. **Residual
assumption:** this is a *knowledge-soundness* statement under the discrete-log / OR-simulation-soundness
assumptions; it is classical and **unaudited**.

*Lifting to the range.* `verifySub` additionally checks `Σ_i C_i·2^i = C` (the homomorphic recomposition). Given
per-bit extraction (each `C_i` opens to `b_i ∈ {0,1}` with known randomness), the committed value equals
`Σ_i b_i·2^i ∈ [0, 2^n)` **as an integer**, provided no wraparound mod `L` — see (d). Applying this to both the
`amount` sub-proof (target `C`) and the `diff` sub-proof (target `C_diff = G^{threshold−1} − C`, reconstructed
by the verifier, not taken from the proof) gives `amount ∈ [0,2^n)` and `diff = threshold−1−amount ∈ [0,2^n)`,
i.e. `0 ≤ amount < threshold`. The verifier reconstructing `C_diff` itself (rather than trusting a
prover-supplied commitment) is load-bearing: it forces the `diff` proof to be about exactly `threshold−1−amount`.

### (b) Honest-verifier zero-knowledge — the OR-composition simulator

*Claim.* Each per-bit OR-proof is HVZK: there is a simulator that, **without the witness**, produces transcripts
identically distributed to honest ones (in ROM, programming the challenge oracle).

*Argument.* The honest prover already runs the CDS simulator on the *false* clause: it samples `s_fake, c_fake`
uniformly and sets `t_fake = H^{s_fake} · P_fake^{−c_fake}`, which makes the false clause verify for *any*
challenge split. For a full simulation (no witness at all), the simulator: (1) samples the overall challenge
`c` (in Fiat–Shamir, this is the value it will **program** the random oracle to return on this transcript);
(2) samples `c_0` uniformly and sets `c_1 = c − c_0`; (3) for **each** clause `j ∈ {0,1}` samples `s_j` uniformly
and sets `t_j = H^{s_j} · P_j^{−c_j}`. Every verification equation holds by construction, and because `s_0, s_1`
are uniform and the `t_j` are determined by them, the simulated `(t_0, t_1, c_0, c_1, s_0, s_1)` is distributed
identically to an honest transcript (where the real clause's `s` is `k + c·r`, uniform because `k` is uniform).
Since `H^r` is **perfectly hiding** (Pedersen), the simulator never needs `r` or `b_i`. The OR structure means
the verifier — and any transcript observer — cannot tell which clause was "real," which is precisely what hides
the bit. ∎(claim)

*Composition.* The range proof is `2n` such OR-proofs (n bits × {amount, diff}) plus the public homomorphic
checks. The bit commitments `C_i` are themselves perfectly hiding, and the per-bit simulators compose (standard
sequential ZK composition in ROM). The amount's confidentiality is therefore **information-theoretic / perfectly
hiding** (consistent with ADR-0006 and ADR-0013): no adversary, classical *or quantum*, recovers `amount` from a
proof — there is no harvest-now-decrypt-later risk to the amount. What is classical is **soundness/binding** (see
the PQ note in Consequences). **Residual assumption:** HVZK + Fiat–Shamir gives non-interactive ZK in the ROM;
the simulator programs the oracle. This is the standard model used for sigma protocols and is **unaudited** here.

### (c) Fiat–Shamir transcript-completeness — is per-bit `statementHash` binding sufficient?

**The weak-FS / Frozen-Heart hazard.** Fiat–Shamir is only sound if the challenge is a hash of **every** public
value the soundness argument quantifies over. If any public input (a generator, a commitment, the statement
parameters, `n`, the threshold, or any first-message `t`) is **omitted** from the hash, a cheating prover can
choose that value *after* seeing the challenge and break soundness — the "Frozen Heart" vulnerability class.

**What the current code binds.** `statementHash(threshold, n, C_amt, amountC, diffC)` hashes the parameters
`(n, threshold)`, the amount commitment, and **all** bit commitments of **both** sub-proofs. Each per-bit
`challenge(...)` then hashes `(stmt, tag, C_i, P_0, P_1, t_0, t_1)`, where `tag` domain-separates per bit and per
sub-proof (`bit/amount/i`, `bit/diff/i`). So the per-bit challenge *transitively* commits to: the full statement
(via `stmt`), the bit index and role (via `tag`), the bit commitment, both clause points, and **that bit's own
first messages** `t_0, t_1`. The generator `H` is currently bound **implicitly** — it is a compile-time
nothing-up-my-sleeve constant (`'PolarSeek/disclosure/generator-H/v1'`), and `G` is the group base — neither is
a hashed input.

**Assessment — sufficient for soundness, but not maximally tight.** For *this* construction the per-bit binding
is **arguably sufficient**, because:
- the statement (all `2n` bit commitments + params) is in **every** challenge via `stmt`, so no bit commitment
  can be chosen adaptively after seeing any challenge;
- each bit's challenge binds **its own** `(t_0, t_1)`, which is what 2-special-soundness for *that* bit needs;
- the homomorphic `Σ C_i·2^i = C` check is verified outside the hash, so the bits cannot be recombined freely.

However, two **honest gaps** remain that the audit should rule on, and which motivate the proposed tightening:

1. **`H` (and `G`) are not hashed into the transcript.** Soundness relies on `dlog_G(H)` being unknown; the proof
   is sound for the *fixed* compile-time `H`. This is fine as long as `H` can never vary, but it makes the
   transcript **not self-describing**: a future code path that parameterized `H` (e.g. per-deployment generator)
   would silently reuse challenges across different generators. **Recommendation:** bind `G` and `H` (their
   compressed bytes) and a protocol/version tag into `statementHash` so the transcript is complete independent of
   compile-time constants. (Low risk, defense-in-depth; matches ADR-0013's "public-input binding" caveat.)

2. **Per-bit challenges are independent hashes, not slices of one transcript-wide challenge.** Today each of the
   `2n` OR-proofs draws its challenge from its own oracle call. The statement is shared, so the bits are jointly
   bound to the *commitments*; but the **first messages** `t_0,t_1` of bit `j` are NOT in the challenge of bit
   `k ≠ j`. Special-soundness is a *per-bit* property and the joint extractor works bit-by-bit, so this does not
   appear to be exploitable for *this* statement. It is nonetheless **looser than the textbook strong-FS ideal**,
   where a single challenge `c = H(public params ‖ G ‖ H ‖ C ‖ all first messages)` binds the *entire* transcript
   in one shot.

**Proposed TIGHTENING (design only; audit-gated).** Adopt **single-transcript binding**: compute one root
challenge `c* = H( domain-tag ‖ G ‖ H ‖ n ‖ threshold ‖ C_amt ‖ {C_i, t^{(i)}_0, t^{(i)}_1}_{all 2n bits} )`
over the *complete* transcript (all bit commitments **and** all bit first-messages of both sub-proofs at once),
then derive each per-bit challenge `c_i = H(c* ‖ "bit" ‖ role ‖ i)` by domain-separated expansion. This:
- makes the transcript **fully self-describing** (generators + params + every first message inside the hash),
  removing both gaps above;
- is the strongest form of Fiat–Shamir for a multi-clause sigma protocol and the easiest for an auditor to
  certify against the Frozen-Heart checklist;
- changes the prover/verifier ordering slightly (all `t`'s must be computed before any challenge — a standard
  commit-then-challenge flow).

**Honest caveat:** the tightening is a **robustness/clarity** upgrade, not a known fix for a known break — we are
**not** asserting the current per-bit binding is exploitable. Whether to ship the tightening, and whether the
current binding is already adequate, is **explicitly deferred to the external audit**. This ADR neither claims
the current code is vulnerable nor that the tightening is proven secure.

### (d) The `n ≤ 251` integer-range / no-wraparound argument

The range conclusion "`Σ b_i·2^i ∈ [0, 2^n)` **over the integers**" only holds if the bit recomposition does not
**wrap modulo `L`**. The verifier therefore hard-caps `n` (it is the verifier's protocol constant, default 32,
NOT read from the proof; a proof with `proof.n ≠ n` is rejected). Two documented failure modes:

- **ZKRANGE-001 (`2^n ≥ L`).** If `n` were large enough that `2^n ≥ L`, the per-bit commitments could encode a
  value that wraps the group order, so a false claim "`< threshold`" could be recombined modulo `L`. Closed by
  capping `n` and by the `proof.n === n` check.
- **ZKRANGE-002 (off-by-one at `n = 252`, found by the Team Apex multi-model audit 2026-06-21).** ristretto255's
  order is `L = 2^252 + d` with `d ≈ 2^124.7`. At `n = 252`, a **negative** `diff` wraps to `L − |diff|`, which
  still lands in `[0, 2^n) = [0, 2^252)`; so a huge `amount` (≈ `2^124`) could falsely prove `< threshold`. The
  fix is the stricter cap **`n ≤ 251`**, i.e. `2^{n+1} ≤ L`. The `+1` margin matters because the argument ranges
  over **two** values whose magnitudes interact (`amount` and `diff = threshold−1−amount`), and `threshold ≤ 2^n`
  pushes intermediate quantities up toward `2^{n+1}`; requiring `2^{n+1} ≤ L` guarantees neither `amount`, `diff`,
  nor the recomposed sums can alias across `L`.

Both `proveBelow` and `verifyBelow` enforce `n ∈ [1, 251]`; `proveBelow` refuses to *emit* a proof at an unsound
bit-length rather than produce one the verifier will reject. **This integer-range argument is the part most
sensitive to a subtle off-by-one and is a priority item for the external audit** (one off-by-one already slipped
to `n=252` before the 2026-06-21 sweep).

## Implementation plan (what would change, behind which flags)

This ADR ships **no code**. Were the audit to ratify the tightening in (c), implementation would be:

- **New, opt-in only.** Add a `transcriptBinding: 'per-bit' | 'single'` (or a `stmt` version bump
  `PolarSeek/disclosure/stmt/v3`) so the current `v2` per-bit path is unchanged and remains the default until the
  audit signs off. No silent behavior change; old proofs keep verifying under `v2`.
- **`statementHash` v3** would additionally absorb `G.toBytes()`, `H.toBytes()`, and an explicit protocol-version
  tag (closing gap (c)(1)) and would be restructured to produce the single root challenge `c*` over all `2n`
  first messages (closing gap (c)(2)).
- **`proveBit`/`verifyBit` reorder** under v3: compute all `t`'s first, derive `c*`, then per-bit `c_i` — a
  commit-then-challenge two-pass, behind the same flag.
- **No change** to the dual-range structure, the `n ≤ 251` cap, the homomorphic checks, or Pedersen commitments.
- **Gating:** nothing merges to the default path until the external ZK/crypto audit reviews the argument in this
  ADR and the v3 transcript. Until then this remains design only.

## KAT / conformance-regen plan

Because this ADR changes nothing, **no vectors regenerate now** and `conformance/vectors/ps-kat.json` /
`ps-negative.json` are untouched; the 23-of-23 conformance and the `zkrange` test suites
(`zkrange.test.ts`, `zkrange.property.test.ts`) are unaffected. Were the v3 tightening implemented later:

- the **default** `v2` KAT vectors would stay byte-identical (back-compat guaranteed by the flag), so C11 and C13
  remain green unchanged;
- a **new** vector set would be added for `v3` transcripts (new statement tag ⇒ different challenge bytes ⇒ a new
  KAT file or a `v3` section), regenerated deterministically from fixed test scalars;
- new **negative** vectors would be added asserting cross-version non-malleability: a `v2` proof must NOT verify
  under a `v3` verifier and vice-versa (distinct `stmt` domain tags guarantee this), plus a Frozen-Heart-style
  negative test that mutating any now-bound public value (`G`, `H`, a foreign `t`) flips verification to `false`;
- property tests (`fast-check`) would be extended to the v3 path. None of this happens in this ADR.

## Alternatives considered

1. **Leave the per-bit binding as-is, document only (no tightening proposal).** Viable — the per-bit `stmt`
   binding is *arguably* already sufficient (see (c)). Rejected as the sole option because it leaves the
   generator unbound and the transcript not self-describing; cheap defense-in-depth is worth proposing to the
   audit. (This ADR keeps it as the *default* until the audit rules.)
2. **Switch range proofs to Bulletproofs / a log-sized inner-product argument.** Smaller proofs, but a *new*
   primitive needing its own audit, and it does not change the soundness *argument* this ADR is asked to record.
   Out of scope; not a Track-B deliverable.
3. **Bind only the generators (gap (c)(1)) without single-transcript binding (gap (c)(2)).** A partial tightening;
   cheaper. Recorded as a fallback if the audit deems full single-transcript binding unnecessary.
4. **Prove `b_i(b_i−1)=0` algebraically instead of an OR-proof.** A different bit-validity gadget; equivalent
   soundness goal, but changes the construction wholesale and discards the audited CDS structure. Rejected.

## Consequences

- **Honest status.** This is an **UNAUDITED, ROM (classical) argument**, not a proof and not a QROM result. The
  Fiat–Shamir transform's soundness in the **QROM** (quantum random-oracle model) is a *separate, stronger*
  question this ADR does **not** address; a quantum adversary against Fiat–Shamir soundness is out of scope here
  and the construction makes **no QROM claim**.
- **Post-quantum profile (unchanged from ADR-0006/0013).** Amount **confidentiality is information-theoretic**
  (Pedersen perfectly hiding) — secure against quantum adversaries, no harvest-now-decrypt-later risk. The
  proof's **soundness/binding is CLASSICAL** (discrete-log): a future quantum adversary able to take discrete
  logs could **forge** an in-range proof for an out-of-range amount. Receipt-envelope integrity remains PQ
  (ML-DSA-87); the ZK proof's integrity is classical; the amount's secrecy is unconditional.
- **No production claim.** Nothing here is "audited," "production-ready," or a non-infringement / FIPS claim. The
  argument is a prerequisite *input* to the external ZK/crypto audit, alongside ADR-0006 and ADR-0013.
- **If ratified,** the tightening makes the transcript self-describing and gives auditors a clean Frozen-Heart
  checklist pass, at the cost of one flagged statement-version and a back-compat vector set. **If not ratified,**
  the current `v2` per-bit binding stands as documented, with this ADR recording the analysis and the residual
  assumptions.
- **Residual assumptions (binding list):** (i) discrete-log / OR-simulation-soundness on ristretto255;
  (ii) SHAKE256 as a random oracle (ROM, not QROM); (iii) `dlog_G(H)` unknown for the fixed nothing-up-my-sleeve
  `H`; (iv) the `n ≤ 251` no-wraparound bound is tight (priority audit item); (v) the linkage contract of
  ADR-0006/0013 (the proof is about the *committed* amount; end-to-end soundness needs the issuer to commit the
  decided amount and bind `C` into the signed receipt).

## References

- `disclosure/src/zkrange.ts` — the construction argued here (`commit`, `proveBit`/`verifyBit`,
  `buildBits`/`proveSub`/`verifySub`, `statementHash`/`challenge`, `proveBelow`/`verifyBelow`; ZKRANGE-001/002).
- `disclosure/test/zkrange.test.ts`, `disclosure/test/zkrange.property.test.ts` — existing tests.
- `conformance/src/suite.ts` — **C11** (range proof hides amount, binds to threshold) and **C13**
  (policy-satisfaction proof, ADR-0006) sit atop this OR-proof.
- ADR-0006 — Zero-Knowledge Policy-Satisfaction Receipts (consumes the dual range proof; UNAUDITED composition;
  PQ profile note).
- ADR-0013 — v:2 commitment-to-intent equality (structural binding; "public-input binding" / range-check caveats
  that this ADR's (c)(1) generator-binding mirrors).
- `docs/STATUS.md` — UNAUDITED-protocol status tracking.
- CDS (Cramer–Damgård–Schoenmakers) OR-composition; Chaum–Pedersen; Fiat–Shamir; the "Frozen Heart" weak-FS
  vulnerability class — the standard literature this argument follows (to be cited precisely by the audit).
