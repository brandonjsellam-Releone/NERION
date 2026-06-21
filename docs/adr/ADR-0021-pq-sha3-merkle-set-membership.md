<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0021 — PQ-sound SHA3-Merkle set-membership for ZK-PSR (proposed, pre-audit)

**Status: PROPOSED — design only, UNIMPLEMENTED. Routes to the external ZK audit / council before any
code lands.** Date: 2026-06-21. This ADR closes the *design* gap for the **deferred ZK set-membership
clause** named in [ADR-0006](./ADR-0006-zk-policy-satisfaction.md) (and in `disclosure/src/policyproof.ts`),
which left "action-type / counterparty ∈ allowed set" unbuilt because the k-way Chaum–Pedersen OR-proof it
needed was un-reviewed and would inherit the **classical** discrete-log soundness of `zkrange`. This is a
*design decision*, not a security result; nothing here is audited or proven, and no part of it is
non-infringement-cleared (FTO is still pending).

## Context

The shipped Policy-Satisfaction Proof (PSP, ADR-0006) proves a **numeric** predicate about a hidden
amount (`amount ≤ ceiling`, optionally `aggregate + amount ≤ cap`) by composing the audited-group dual
range proof in `disclosure/src/zkrange.ts`. It deliberately **defers two membership clauses**:

> "The ZK SET-MEMBERSHIP clauses (action-type / counterparty) are DEFERRED: they need a new k-way
> Chaum-Pedersen OR-proof that is not yet built or reviewed, and the unsalted selective-disclosure
> fallback is deliberately NOT used here (it is brute-forceable over small enumerable domains)."
> — `disclosure/src/policyproof.ts`

The gap is real: a governor that wants to attest "the decided action's *type* (or *counterparty*) was on
the policy's allow-list — without revealing **which** one" has no sound, privacy-preserving primitive
today. The two candidate routes both have problems:

1. **k-way Chaum–Pedersen OR-proof over ristretto255** (the route ADR-0006 sketched). Sound, but its
   binding/soundness rests on **discrete-log** over ristretto255 — a **classical** assumption. A future
   quantum adversary could **forge** a membership proof for a value that is *not* in the allowed set, in
   exactly the same way ADR-0006 notes a quantum adversary could forge a range proof. It also costs one
   OR-branch per set element, so the proof and the verifier both grow linearly in the set size.
2. **Unsalted selective disclosure** (`selective.commitField` without a salt). Brute-forceable over small
   enumerable domains (the RCPT-001 / CB-001 class, [ADR-0014](./ADR-0014-salted-intent-commitment.md)) —
   already rejected for this exact use by `policyproof.ts`.

Meanwhile `translog/src/merkle.ts` already gives the project a **production-grade, RFC 6962-style SHA3
Merkle machinery** — leaf/node domain separation (`0x00`/`0x01` prefixes), `merkleRoot`, `inclusionProof`,
and `verifyInclusion` (Trillian index decomposition) — whose only cryptographic trust assumption is **SHA3
collision-resistance**, the same hash trust the whole receipt/transparency layer already depends on. SHA3
collision-resistance is a **symmetric / hash** assumption with no known quantum break beyond a generic
Grover-style quadratic speed-up (which 256-bit output already accounts for at a ≥128-bit security floor).

**The design opportunity:** prove set-membership the *transparency-log* way — a SHA3 Merkle inclusion path
to a committed allow-list root — so the membership proof's **soundness is PQ** under the *existing* SHA3-CR
trust assumption, rather than re-importing a fresh classical discrete-log assumption for the verb/counterparty
clause. This makes the new clause **strictly stronger** (PQ-sound) than the OR-proof ADR-0006 contemplated,
while **reusing** code the project already ships and tests, rather than introducing a new algebraic accumulator.

## Decision

**Adopt a SHA3-Merkle set-membership proof for the ZK-PSR membership clause**, bound into the
Fiat–Shamir transcript and **fenced behind a new `allowUnauditedZk` flag** (see Implementation plan).
The construction reuses `translog/src/merkle.ts` verbatim as a library — no new hash, no new accumulator,
no new algebraic primitive.

### Construction (proposed)

Let the policy fix a **public allowed set** `S = { e₀, e₁, …, e_{k-1} }` for the clause in question (e.g.
the allow-list of action-type identifiers, or of counterparty identifiers). Each element is encoded
canonically (dCBOR via `encodeCanonical`, with a clause-specific domain tag so an action-type set can never
be confused with a counterparty set).

1. **Allowed-set commitment (public, by the policy).** The policy author sorts `S` by canonical encoding
   (deterministic, dedup'd — so the set's identity is its *contents*, not an ordering an adversary can
   permute), builds the SHA3 Merkle tree over the encoded elements using the existing
   `merkleRoot(entries)`, and publishes the **root** `R_S` and the set **size** `k` as part of the signed
   policy. `R_S` is the public commitment to the allowed set. (Domain-separated leaf hashing is already
   `leafHash(data) = SHA3(0x00 ‖ data)`; node hashing `nodeHash(l,r) = SHA3(0x01 ‖ l ‖ r)`.)

2. **Membership witness (private, by the prover).** The decided element `e* ∈ S` sits at some index `m`.
   The prover obtains its **inclusion path** `π = inclusionProof(encoded(S), m)` and the index `m`. The
   element `e*` and its index `m` are the **secret**; only `R_S` and `k` are public.

3. **Hiding the element.** A bare Merkle path reveals `e*` (the leaf) and `m` (the path directions). To
   keep the *which-element* private we **commit to the leaf and the index** and prove consistency in
   zero-knowledge against `R_S`. Two composable options are specified; the ADR proposes **(3a)** as the
   minimal sound default and records **(3b)** as the privacy-maximal upgrade:

   - **(3a) Salted leaf + path, disclosed to the auditor (minimal, sound, NOT element-hiding to the
     auditor).** Leaves are **salted** per RCPT-001 / ADR-0014: the tree is built over
     `leaf_i = SHA3(domain ‖ salt_i ‖ encoded(e_i))` with per-element high-entropy salts. The prover
     reveals `(e*, salt_*, m, π)` to the **auditor only** (not to the public log), who runs
     `verifyInclusion(m, k, leaf_*, π, R_S)` and checks `leaf_* = SHA3(domain ‖ salt_* ‖ encoded(e*))`.
     This proves "`e*` is one of the committed allowed elements" with **PQ soundness** (SHA3-CR) and
     hides `e*` from anyone **without** the disclosed witness (the public artifact carries only `R_S`),
     but it does **not** hide `e*` from the auditor it discloses to. This is the honest, minimal step: it
     replaces the brute-forceable unsalted fallback with a sound, salted, PQ membership attestation.
   - **(3b) ZK Merkle-path (element-hiding even to the verifier) — DEFERRED within this ADR.** To hide
     `e*` from the *verifier* as well, the SHA3 path must be checked **inside a zero-knowledge proof of a
     hash pre-image relation** (a STARK/IOP-style or hash-based circuit proving "I know `(e*, m, π)` such
     that folding `π` from `leaf(e*)` yields `R_S`"). This is genuinely PQ (it proves a SHA3 relation, no
     discrete log), but it is a **substantial new primitive** (a hash-based SNARK/STARK over the
     SHA3 compression function) that this ADR does **not** design or adopt — it is named as the
     element-hiding successor and routed to the same audit. The MVP (3a) is what this ADR proposes to
     build first.

### Transcript binding (Fiat–Shamir)

When the membership clause is **composed** with the existing PSP range proofs into a single ZK-PSR, its
public inputs **must** be folded into the **same Fiat–Shamir transcript** that already binds the range
proof's full statement — to prevent a mix-and-match across independently-generated sub-proofs (the
"weak Fiat–Shamir / Frozen Heart" class the council already closed for `zkrange`, see the `statementHash`
construction in `zkrange.ts`).

Concretely, extend the PSP statement hash so the membership clause contributes, **before** any challenge
is derived:

```
stmt = SHAKE256(
  "Nerion/disclosure/zkpsr-stmt/v1"
  ‖ <existing range-proof statement bytes>            // n, thresholds, C_amount, all bit commitments
  ‖ "membership"
  ‖ clauseDomain                                       // e.g. "action-type" | "counterparty"
  ‖ R_S                                                // allowed-set Merkle root (public)
  ‖ uint(k)                                            // allowed-set size (public, verifier-fixed)
  ‖ C_member                                           // commitment(s) the membership clause exposes (3a: none beyond R_S; 3b: the ZK proof's public inputs)
, dkLen=64)
```

and bind that same `stmt` into the membership clause's own challenge derivation, mirroring
`zkrange.challenge(stmt, …)`. The **verifier fixes `k` as a protocol/policy constant** (exactly as
`verifyBelow` fixes `n` and never reads it from the proof), so a prover cannot present a path against a
different-sized or attacker-chosen tree. `R_S` is taken from the **signed policy**, never from the proof.
Finally, the whole ZK-PSR digest (range + membership) is bound under one `policyProofDigest`-style value
carried in the receipt body, so it is transitively ML-DSA-87-signed and transparency-log-anchored exactly
like the v:2 PSR (ADR-0006 / ADR-0013).

## Soundness / Security argument (UNAUDITED — design rationale only)

**Claim (membership soundness, 3a).** Under SHA3 collision-resistance, a prover cannot produce a valid
`(leaf_*, m, π)` that `verifyInclusion(m, k, leaf_*, π, R_S)` accepts for a `leaf_*` not equal to one of
the `k` committed allowed leaves. **Argument:** `verifyInclusion` recomputes `R_S` by folding `π` from
`leaf_*` using the fixed RFC 6962 hashing (`leafHash`/`nodeHash`). If an accepting witness existed for a
leaf outside the committed set, the two distinct leaf-sets folding to the **same** root `R_S` would exhibit
a **SHA3 collision** in the leaf/node hash chain — contradicting SHA3-CR. The salted-leaf binding
(`leaf_* = SHA3(domain ‖ salt_* ‖ encoded(e*))`, RCPT-001 form) ties the path's leaf to the *element*, so
acceptance attests membership of the *element*, not merely of an opaque leaf byte-string. This is the same
soundness the transparency log already relies on for receipt inclusion; the membership clause inherits it
**unchanged**.

**Why this is PQ-sound where the OR-proof is not.** The OR-proof's soundness reduces to **discrete-log**
over ristretto255 (a *classical* assumption a quantum adversary breaks → forge a membership proof for a
non-member). The SHA3-Merkle proof's soundness reduces to **SHA3 collision-resistance** (a *symmetric/hash*
assumption with no known quantum break beyond Grover's quadratic speed-up, which 256-bit output already
budgets for ≥128-bit collision security). So the membership clause becomes **PQ-sound under the project's
already-relied-upon SHA3-CR trust**, rather than importing a fresh classical assumption. This is a genuine
upgrade over the route ADR-0006 contemplated, and it is the property that lets the deferred clause be closed.

**Residual assumptions / honest caveats (binding):**

- **ROM caveat (Fiat–Shamir).** Making the membership clause non-interactive uses the **random-oracle
  model** for the SHAKE256-based challenge, exactly as `zkrange`/PSP do. The construction's *interactive*
  soundness rests on SHA3-CR; its *non-interactive* soundness additionally rests on the ROM heuristic.
  Neither the ROM instantiation nor a **QROM** analysis is done here — treat NI-soundness against a
  **quantum** Fiat–Shamir adversary as **UNPROVEN, not guaranteed**, the same nuance ADR-0006 records for
  the PSP's zero-knowledge in the QROM.
- **Element-hiding is bounded by the chosen mode.** Mode **(3a)** hides `e*` from the public artifact but
  **discloses it to the auditor** it proves to — it is a sound, salted membership *attestation*, not a
  verifier-blind ZK proof. Full element-hiding (the verifier learns only "∈ S") needs mode **(3b)**, a
  hash-based ZK circuit this ADR explicitly does **not** design. Do not claim "the verifier learns nothing
  about which element" for the MVP.
- **Salt management.** Per-leaf salts must be high-entropy and unique (RCPT-001 / ADR-0014 discipline);
  reuse relinks elements across proofs and weakens hiding.
- **Set integrity is the policy signer's job.** `R_S` and `k` must come from the **signed** policy. A
  malicious policy author who lists the wrong allowed set is out of scope here (that is the
  quorum/attestation model's job, as in ADR-0013/0014) — this clause attests *membership in the committed
  set*, not that the committed set is the *right* set.
- **32-bit tree-size bound (TLOG-002).** The reused verifier (`rootFromInclusion`) is only sound for
  `k < 2^31` (documented in `merkle.ts`); allow-lists are tiny, so this is non-binding in practice, but the
  membership verifier MUST inherit the same fail-closed bound rather than compute over a wrong tree shape.
- **UNAUDITED / PROPOSED.** Nothing here has had external cryptographic review. No soundness, hiding, or
  ZK property is *proven* or *audited*; no FIPS/CNSA conformance is claimed for the membership clause; no
  non-infringement (FTO) position is asserted. This ADR records a design to be reviewed, not a result.

## Implementation plan (proposed — gated, no behavior change yet)

**What changes (when, after audit, this is built):**

- New module `disclosure/src/setmembership.ts` (proposed): `commitAllowedSet(elements, clauseDomain)` →
  `{ root, size }` (thin wrapper over `merkleRoot` + salted `leafHash`); `proveMembership(element, salt,
  set)` → `{ index, path, salt }`; `verifyMembership(witness, root, size, clauseDomain)` (thin wrapper over
  `verifyInclusion`, fixing `size` as a protocol constant and inheriting the TLOG-002 bound). It **imports**
  `translog/src/merkle.ts` — it does **not** re-implement Merkle hashing.
- `policyproof.ts` gains an **optional** membership clause whose public inputs are folded into the PSP
  statement hash (transcript binding above) and into `policyProofDigest`. The numeric-only PSP path is
  **unchanged** when no membership clause is requested (backward-compatible, default-off).
- `PolicyBounds` gains optional `allowedSets?: { actionType?: SetCommitment; counterparty?: SetCommitment }`
  carrying `{ root, size, clauseDomain }`.

**Behind which flag (the fence).** All of the above is gated behind a single **`allowUnauditedZk`** flag
(the flag named in `docs/APEX_SPRINT_BACKLOG.md` for this item). Default **false**: with the flag off, the
membership API is inert / refuses to emit or accept a membership clause, so the **unaudited** primitive
cannot be reached on a default build — exactly mirroring how the rest of `disclosure/` is marked UNAUDITED
and kept out of any production-privacy path. The flag is the explicit operator opt-in that this is
pre-audit ZK. **No production-privacy claim** is made while the flag exists.

**KAT / conformance-regen plan.** When implemented (not in this ADR): add a deterministic membership KAT
(fixed allowed set + fixed salts → fixed `R_S`, a positive inclusion witness, and a tamper case) under the
disclosure tests, regenerate any affected vectors, and add a new conformance check **C24** asserting (i) a
member verifies against `R_S`, (ii) a **non-member** path is rejected, (iii) a path against a
**wrong-size** `k` is rejected (verifier-fixed `k`), and (iv) with `allowUnauditedZk=false` the clause is
unreachable. Bump the conformance count (23 → 24) and `docs/STATUS.md` / `docs/ASSURANCE.md` accordingly.
**None of this happens in this ADR** — this ADR is design only and changes no code, KAT, or count.

## Alternatives considered

1. **k-way Chaum–Pedersen OR-proof over ristretto255 (the ADR-0006 sketch) — REJECTED as the primary.**
   Sound and element-hiding to the verifier, but its soundness is **classical** discrete-log (quantum-forgeable)
   and it costs O(k) per proof and verify. The SHA3-Merkle route is **PQ-sound** under the existing SHA3-CR
   trust and reuses shipped, tested code. (The OR-proof remains a *possible* element-hiding alternative if one
   accepts the classical assumption; it is recorded, not adopted.)
2. **RSA / discrete-log / bilinear accumulators (e.g. dynamic universal accumulators) — REJECTED.** Compact
   and element-hiding, but their security rests on **classical** number-theoretic assumptions (Strong-RSA /
   q-SDH / discrete-log) that a quantum adversary breaks — re-importing exactly the assumption this ADR is
   trying to avoid, plus a trusted-setup or new-primitive burden. A SHA3 Merkle root is the **hash-based,
   PQ, no-trusted-setup** accumulator the project already has.
3. **Unsalted selective disclosure (`commitField` without salt) — REJECTED.** Brute-forceable over small
   enumerable domains (RCPT-001 / CB-001 class), already rejected for this use in `policyproof.ts`.
4. **Lattice-based set-membership (e.g. one-out-of-many over Module-LWE) — DEFERRED.** Genuinely PQ and
   verifier-blind, but a heavy new primitive with its own assumptions and no reuse of existing machinery;
   out of scope for closing the deferred clause minimally. Named as a future element-hiding option alongside
   (3b).
5. **Build the full element-hiding ZK Merkle circuit (3b) now — DEFERRED.** It is the right *end state* for
   verifier-blind membership, but it is a substantial hash-based SNARK/STARK effort; this ADR proposes the
   sound, salted MVP (3a) first and routes (3b) to the same audit track.

## Consequences

- **Closes the deferred ZK-PSR membership clause *in design*** with a **PQ-sound** construction, removing
  the last "needs a new, un-reviewed classical primitive" blocker ADR-0006 recorded — and does so by
  **reusing `translog/merkle.ts`**, so the new surface is thin wrappers, not new cryptography.
- **Strictly stronger soundness than the OR-proof** the original plan contemplated: membership soundness
  becomes PQ (SHA3-CR) instead of classical (discrete-log).
- **Honest privacy ceiling for the MVP:** mode (3a) is a *salted, sound, PQ membership attestation* that
  discloses the element to the auditor; verifier-blind element-hiding remains future work (3b / lattice).
  No over-claim of verifier-blind ZK for the MVP.
- **No behavior change now.** This ADR ships **one file**. The primitive, the flag, the KAT, and the C24
  conformance check are all **deferred to a reviewed implementation**; the default build is unchanged and
  the new path, when built, is **off by default** (`allowUnauditedZk=false`).
- **Routed to audit.** This design is handed to the external ZK audit / council (the same track as the rest
  of `disclosure/`). It is **UNAUDITED and PROPOSED**; no soundness/hiding/ZK property is proven or audited,
  no FIPS/CNSA claim is made for the clause, and no FTO / non-infringement position is asserted.

## References

- [ADR-0006 — Zero-Knowledge Policy-Satisfaction Receipts](./ADR-0006-zk-policy-satisfaction.md) (defers the
  set-membership clause this ADR closes in design).
- [ADR-0013 — v:2 commitment-to-intent binding](./ADR-0013-v2-commitment-equality.md) (linkage contract;
  how the ZK-PSR digest is bound into the signed receipt).
- [ADR-0014 — Salted / hiding v:1 intent commitment](./ADR-0014-salted-intent-commitment.md) (RCPT-001
  salted-leaf discipline reused for the membership leaves; brute-force class avoided).
- `disclosure/src/policyproof.ts` — the PSP and the DEFERRED-membership note this ADR addresses.
- `disclosure/src/zkrange.ts` — `statementHash` / `challenge` strong-Fiat–Shamir binding the membership
  clause folds into.
- `disclosure/src/selective.ts` — salted commitment form (`commitField(value, salt)`) reused for leaves.
- `translog/src/merkle.ts` — RFC 6962 SHA3 Merkle machinery reused verbatim (`merkleRoot`,
  `inclusionProof`, `verifyInclusion`, TLOG-002 32-bit bound).
- `docs/APEX_SPRINT_BACKLOG.md` (item B6) — the `allowUnauditedZk` fence + ZK-audit routing this ADR
  realizes.
