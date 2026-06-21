<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0022 — Post-quantum commitment migration preserving the v:2 SHA3 binding (proposed, research)

**Status: PROPOSED — DESIGN ONLY, UNIMPLEMENTED, RESEARCH-TRACK.** This ADR records a *decision
about the direction and shape* of migrating the disclosure layer's commitment primitive from the
classical ristretto255 Pedersen commitment to a **post-quantum (PQ) binding** commitment, while
preserving the v:2 SHA3 commitment-binding from ADR-0018 (built on ADR-0013). It changes **no**
code, **no** KAT vector, and **no** behaviour. The construction below is **UNAUDITED** and is
explicitly **gated behind external audit + primitive standardization**; implementation is
**deferred**. Nothing here is a soundness, security, audited, production-ready, FIPS-validated, or
non-infringement claim. Date: 2026-06-21. Track-B item **B7**. Routes to the same external ZK /
crypto audit track that gates ADR-0006 / ADR-0013 / ADR-0016 / ADR-0018 (`docs/STATUS.md`,
`docs/ASSURANCE.md`).

This ADR formalizes the **"top forward upgrade"** already flagged in `docs/STATUS.md`: *"migrate the
commitment layer from classical Pedersen/ristretto255 to a post-quantum commitment scheme (lattice-
or hash-based), preserving the v:2 SHA3 binding … this makes the ZK layer's soundness post-quantum
end-to-end."* It is the design record for that line; it does not implement it.

## Context

### The honest cryptographic picture today (do not get this backwards)

The disclosure stack commits to an action's amount with a **Pedersen commitment over the audited
prime-order group ristretto255** (`disclosure/src/zkrange.ts:70-72`):

```
commit(v, r) = v·G + r·H            (G = Point.BASE; H = NUMS hash-to-curve, ADR-0016)
```

Two independent, often-confused security properties hang off this one line. The project's standing
discipline — corrected by the multi-model crypto council and recorded verbatim in
`disclosure/src/policyproof.ts:27-40` — is to keep them separate:

- **Hiding (the amount's secrecy) is PERFECT / information-theoretic, and therefore already
  post-quantum.** A Pedersen commitment is perfectly hiding for *any* generator pair: for every
  candidate value `v'` there is a blinding `r'` with `v'·G + r'·H = C`, so `C` carries *zero*
  Shannon information about `v`. No adversary — **including a CRQC (cryptographically relevant
  quantum computer)** — can recover the amount from a logged commitment or receipt leaf. There is
  **no harvest-now-decrypt-later risk to the hidden amount.** This property is **not** what this ADR
  changes or needs to change.

- **Binding (the proof's soundness) is only CLASSICAL.** Computational binding of `v·G + r·H`
  reduces *exactly* to "no one knows `t = dlog_G(H)`" (the assumption ADR-0016 pins and
  fail-closes the trivial breaks of). Discrete log over ristretto255 is broken in polynomial time
  by **Shor's algorithm** on a CRQC. If an adversary can compute `t`, then for any
  `C = v·G + r·H = (v + t·r)·G` they can produce a *second* opening `(v', r')` with
  `v' + t·r' = v + t·r` — i.e. **forge a commitment that opens to an out-of-bounds amount**, and
  the range / policy-satisfaction proof built over `C` (`zkrange.ts`, `policyproof.ts`, ADR-0006)
  would then **verify a false statement**. So a CRQC does **not** break the amount's secrecy; it
  breaks the *integrity* of the compliance verdict.

This asymmetry is the whole motivation: **the amount's confidentiality is already PQ; the proof's
soundness is the transitional, classical weak point.** This ADR targets *binding/soundness only*.

### What is already PQ in the receipt path (and must be preserved)

The v:2 commitment-binding established by **ADR-0013** (structural binding) and specified end-to-end
by **ADR-0018** (canonical `u64` amount domain + additive v:2 `ReceiptBody`) ties the commitment to
the intent and to the signed, transparency-logged receipt body **using SHA3**, not the group:

- `commitbind.ts` `boundIntentDigest(intent, C) = SHA3-256(dCBOR{domain, intent-skeleton, C.toBytes()})`
  binds the commitment *point bytes* to the exact intent skeleton (amount excluded per CB-001 so the
  public digest never makes the amount brute-forceable).
- ADR-0018's additive v:2 `amount` block carries `{ domain, commitment, boundDigest, psr, n }` under
  the **ML-DSA-87** signature and the RFC 6962 transparency log.

**The SHA3 binding is already post-quantum.** SHA3-256 against a quantum adversary is governed by
Grover/BHT: preimage resistance degrades from ~256 to ~128 bits, collision resistance from ~128 to
~85 bits (BHT) — both comfortably above the protocol's target floor, and *independent of any group
assumption*. The receipt-envelope integrity (ML-DSA-87) is PQ. **So the only classical link in the
chain is the commitment primitive's *binding* and the discrete-log soundness of the ZK proof over
it.** This ADR's central design constraint is therefore:

> **Swap the commitment primitive for a PQ-binding one, leaving the SHA3 binding (ADR-0013/0018) and
> the ML-DSA-87 / RFC 6962 envelope exactly as-is.** The binding hashes commitment *bytes*; if the
> new primitive exposes canonical, fixed-layout bytes, the SHA3 binding survives unchanged.

### Why this is research-track, not the next sprint

Unlike ADR-0016 (pin `H`) or ADR-0018 (schema wiring of existing primitives), this migration
*replaces a cryptographic primitive* and *changes the proof system over it*. There is no drop-in,
standardized, audited PQ commitment-with-efficient-range-proof that the project can adopt today. The
honest state of the art is unsettled (see Alternatives). Committing to a specific primitive now would
be premature; this ADR fixes the **target shape, the invariants to preserve, the decision criteria,
and the open problems**, and explicitly **defers selection and implementation** to after external
audit + primitive standardization. It is a *direction-setting* record, the strongest honest output
at this stage.

## Decision

**Adopt, as a research-track direction (not an implementation), a migration to a post-quantum
*binding* commitment primitive that preserves perfect/strong hiding and keeps the v:2 SHA3 binding
of ADR-0013/0018 intact, gated behind external audit and primitive standardization.** Concretely:

### (a) The migration target — a PQ-binding, (computationally) hiding commitment with a byte canon

Introduce a commitment abstraction `PqCommitment` with the *same external contract* the SHA3 binding
depends on: a deterministic, canonical, fixed-layout byte encoding `C.toBytes()`. The candidate
primitive families (selection deferred — see Alternatives) are:

- **Hash-based commitment** — `C = H(v ‖ r)` / a Merkle-style commitment with a high-entropy `r`,
  using the already-present SHA3/SHAKE256. **Binding** reduces to collision/preimage resistance of
  SHA3 (PQ, Grover/BHT-bounded); **hiding** is *computational* (hiding the low-entropy `v` behind a
  high-entropy `r`, exactly the ADR-0014 salted-commitment pattern). This trades Pedersen's
  *perfect* hiding for *computational* hiding — a deliberate, explicitly-flagged change (see
  Consequences). It is the *simplest* PQ-binding option but is **not homomorphic**, which breaks the
  current range-proof construction (the bit-decomposition + `shiftCommitment` homomorphism in
  `zkrange.ts` depends on group additivity), so it requires a different proof system (e.g. a
  hash-based / MPC-in-the-head / STARK-style range argument).

- **Lattice-based (Module-SIS / Module-LWE) commitment** — e.g. an Ajtai/`A·s`-style commitment with
  short randomness. **Binding** reduces to Module-SIS (a PQ assumption); **hiding** to Module-LWE,
  and it retains a *linear/additive homomorphism* that a lattice range argument (e.g.
  Bulletproofs-over-lattices / lattice Σ-protocols) can exploit, more structurally analogous to
  today's construction. This is the more *feature-preserving* family but the *less mature / heavier*
  one, and its concrete-security parameters are still moving.

The **decision criterion** for eventual selection (recorded so the audit/standardization gate has a
target): pick the family that (i) has a **standardized or standardization-track** primitive with
public concrete-security parameters, (ii) admits an **auditable range / policy-satisfaction proof**
whose soundness is PQ, (iii) exposes a **canonical byte encoding** so ADR-0013/0018's SHA3 binding is
reused verbatim, and (iv) keeps hiding at least computationally PQ (ideally perfect/statistical).
**No family is selected in this ADR.**

### (b) Preserve the v:2 SHA3 binding verbatim (the load-bearing invariant)

The binding in `commitbind.ts` / ADR-0018 hashes `commitment.toBytes()`; it is **agnostic to what
the commitment *is*** so long as the bytes are canonical and fixed-layout. The migration therefore:

- Keeps `boundIntentDigest(intent, C) = SHA3-256(dCBOR{domain, intent-skeleton, C.toBytes()})`
  **unchanged in structure** — only the *provenance* of `C.toBytes()` changes (PQ commitment instead
  of ristretto255 point). CB-001 still holds: the amount stays out of the digest preimage.
- Keeps ADR-0018's additive v:2 `amount` block shape; the new primitive rides in via the
  **`domain` discriminator** ADR-0018 already provisioned for exactly this:
  `amount.domain: "u64/pq"` (vs the classical `"u64"`). This is a **new versioned commitment domain,
  not a v:1/v:2 schema break** — ADR-0018 explicitly designed `amount.domain` to let "a future
  PQ-commitment migration introduce `domain: "u64/pq"` without another schema break."
- Keeps ML-DSA-87 signing + RFC 6962 anchoring of the body **unchanged**.

Net: the **only** thing that becomes PQ is the commitment's binding and the soundness of the proof
over it. Everything the receipt envelope already does in PQ stays as-is; no second schema break.

### (c) A new, separately-audited PQ proof system over the new commitment

The current range proof (Pedersen bit-commitments + Chaum–Pedersen OR-proofs + strong Fiat–Shamir,
`zkrange.ts`) is **discrete-log-soundness-bound** and cannot be reused over a PQ commitment. The
migration replaces it with a **PQ-sound range / policy-satisfaction argument** matched to the chosen
primitive (hash-based/STARK-style for a hash commitment; a lattice range argument for a lattice
commitment). This proof system is the **largest new audit surface** and the principal reason for the
audit + standardization gate.

### (d) Explicit QROM scope note — quantum soundness of the proof is UNPROVEN

The current PSP's zero-knowledge and Fiat–Shamir soundness are argued in the **classical random-oracle
model (ROM)**, *not* the **quantum random-oracle model (QROM)** — this is stated verbatim in
`policyproof.ts:37-40` and carried in ADR-0018. **Migrating the commitment to a PQ-binding primitive
does NOT by itself make the proof QROM-sound.** A Fiat–Shamir non-interactive argument is sound
against a quantum adversary only with a **QROM** analysis (Grover speedups on the hash oracle,
adaptive quantum queries, the measure-and-reprogram / lifting techniques of Don–Fehr–Majenz–Schaffner
and follow-ups). This ADR therefore records, as a **hard, explicit, UNPROVEN residual**:

> **The quantum soundness of the range / policy-satisfaction proof (its Fiat–Shamir transform in the
> QROM, and the PQ-soundness of the underlying interactive argument) is UNPROVEN and is an external-
> audit obligation. PQ *binding of the commitment* is necessary but NOT sufficient for end-to-end PQ
> soundness; the *proof system over it* must also be QROM-analyzed.** We claim neither a ROM nor a
> QROM result here.

This is the single most important honesty point of the migration: it is easy to claim "PQ commitment
⇒ PQ-sound proof," and it is **false** without the QROM analysis of the proof transform.

## Soundness / security argument (intended, NOT proven; routes to audit)

This states what the migration is *intended* to achieve and, explicitly, what it does **not**
establish. **Nothing here is proven; all of it routes to external audit + standardization.**

- **Intended gain.** After migration, an adversary with a CRQC could **no longer forge a
  commitment-opening** to an out-of-bounds amount via Shor on discrete log, because binding would
  reduce to a PQ assumption (SHA3 collision-resistance for a hash commitment; Module-SIS for a
  lattice commitment) instead of dlog over ristretto255. Combined with a **QROM-sound** proof
  transform (item (d), an audit obligation), the compliance verdict's *integrity* would become PQ
  end-to-end — matching the already-PQ secrecy and already-PQ receipt envelope.

- **Preserved, not newly claimed — hiding/secrecy.** The amount's confidentiality is *already*
  information-theoretic/PQ under Pedersen and remains at least **computationally PQ** under the new
  primitive (perfect/statistical for a suitable lattice commitment; computational for a hash
  commitment). For a hash commitment this is a **downgrade from perfect to computational hiding** —
  flagged loudly in Consequences. The migration's *purpose* is binding, and it must be designed so it
  does not *silently* weaken hiding below the computational-PQ floor.

- **Preserved, not touched — the SHA3 binding and the envelope.** ADR-0013/0018's SHA3 binding and
  the ML-DSA-87 / RFC 6962 envelope are unchanged; their PQ properties (Grover/BHT-bounded SHA3,
  ML-DSA-87 signatures) carry over verbatim. The migration is deliberately scoped to *not* re-open
  these.

- **UNPROVEN residuals, explicit:**
  - **QROM (item d).** The proof's quantum soundness/zero-knowledge under Fiat–Shamir is **not
    analyzed in the QROM**. UNPROVEN. Top audit obligation.
  - **Primitive concrete security.** Module-SIS/LWE parameter selection (and any hash-commitment
    domain separation / randomness length) must hit a stated PQ security level; parameters are still
    moving in the literature and **not pinned here**.
  - **Hiding regime.** Whether the chosen primitive is perfectly, statistically, or only
    computationally hiding — and whether that is acceptable for the threat model — is an audit
    decision, not asserted here.
  - **Byte-canonicalization.** The new `C.toBytes()` must be canonical and fixed-layout so the SHA3
    binding stays collision-resistant over it (no malleable encodings); confirmed byte-exact by audit
    + KAT.
  - **Trust model unchanged.** As in ADR-0013/0018, binding does **not** defend against a kernel/
    binder malicious *at admission* — that remains the decentralized-quorum / attestation model's
    job. A PQ commitment removes the *quantum-forgery* attack on soundness, **not** the
    *corrupt-admitter* attack.
  - **No primitive is selected.** Choosing hash- vs lattice-based, and the exact construction, is
    deferred to the standardization + audit gate.

No claim in this section is audited, proven, production-ready, FIPS-validated, or a non-infringement
statement.

## Implementation plan (deferred; what *would* change, behind which flags)

**Implementation is deferred** until (1) a suitable PQ commitment primitive is standardized or on a
credible standardization track with public concrete-security parameters, and (2) external audit has
reviewed the binding + QROM arguments. When (and only when) those gates clear, the *additive,
flag-gated* shape would be:

1. **`disclosure/src/pqcommit.ts` (new, additive).** A `PqCommitment` abstraction with
   `pqCommit(v, r)`, `pqOpen`, and a canonical `toBytes()` — mirroring the `commit` / `Pt` surface so
   `commitbind.ts` and `policyproof.ts` can be parameterized over the commitment type rather than
   hard-wired to ristretto255. No edit to the classical path.
2. **`disclosure/src/pqrange.ts` (new, additive).** The PQ-sound range / policy-satisfaction argument
   matched to the chosen primitive. The classical `zkrange.ts` / `policyproof.ts` are **untouched**;
   the PQ proof lives beside them.
3. **`commitbind.ts` — unchanged in structure.** `boundIntentDigest` keeps hashing `C.toBytes()`;
   only the concrete commitment type behind `C` differs on the PQ path. CB-001 preserved.
4. **`receipts/` — reuse ADR-0018's `amount.domain` discriminator.** A PQ receipt sets
   `amount.domain: "u64/pq"`; the v:2 body shape is otherwise as ADR-0018 specifies. **No new schema
   break** — this is a new commitment domain inside the already-additive v:2 block. v:1 and classical
   v:2 (`"u64"`) bytes/KATs are byte-identical and untouched.
5. **Flag.** A `PQ_COMMITMENT` build/feature flag (off by default, and *additionally* gated by the
   audit/standardization sign-off) selects the PQ commitment + PQ proof + `"u64/pq"` domain. With the
   flag off, code path, emitted bytes, and KATs are exactly today's.

**KAT / conformance-regen plan (classical frozen, PQ added — when implemented):**

- **Classical KATs are NOT regenerated.** `conformance/vectors/ps-kat.json` and all existing
  ristretto255 / SHA3 / ML-DSA-87 vectors stay **byte-identical**; the PQ path is a new `domain`
  value, so no existing leaf or vector changes.
- **New PQ vectors are ADDED** (e.g. a `pq:` section / `PS-KAT-PQ` set): a frozen
  `(intent, v, r, C, bounds, proof)` tuple with the expected canonical `C.toBytes()`,
  `boundDigest = SHA3-256(...)`, `psr`, canonical `"u64/pq"` v:2 body bytes, and the ML-DSA-87
  signature — *additive* fixtures, never substituted.
- **New conformance check (next free C-id at implementation time).** Assert: (1) the PQ commitment
  is well-formed and its bytes are canonical/fixed-layout; (2) `boundIntentDigest` over the PQ `C`
  matches and excludes the amount (CB-001); (3) a privacy verifier validates the PQ amount block
  **without** the amount/opening; (4) the classical paths remain byte-identical with the flag off.
  Wire into the conformance count/registry per the repo's bookkeeping. (No C-id is reserved here —
  this ADR is design-only.)
- **Re-verification:** full conformance + KAT with `PQ_COMMITMENT` off (byte-identical to today) and
  on (PQ vectors + new check pass). The grant/milestone is met only when both hold **and** external
  audit has reviewed the binding + QROM arguments **and** the primitive is standardized.

## Alternatives considered

1. **Status quo — keep classical Pedersen/ristretto255, document the gap — REJECTED as the
   end-state, ACCEPTED as the interim.** The amount's secrecy is already PQ and the receipt envelope
   is PQ, so the *interim* posture (classical proof soundness, clearly disclosed) is honest and
   acceptable *until* a CRQC is plausible. But leaving proof soundness classical *forever* means a
   CRQC could forge compliance verdicts; the migration direction must be on record. So: status quo is
   the documented interim; this ADR is the forward plan, deferred behind the gate.
2. **Hash-based commitment (`H(v‖r)`) + hash/STARK-style range argument — CANDIDATE, not selected.**
   Smallest, most-mature primitive (reuses SHA3, PQ binding via collision-resistance), and the
   hiding-by-high-entropy-`r` pattern is *already* used in ADR-0014. **But** it is **non-homomorphic**
   (breaks the current bit-decomposition + `shiftCommitment` range proof) and only **computationally
   hiding** (a downgrade from Pedersen's perfect hiding). Viable, with an explicit hiding-regime
   trade-off the audit must accept.
3. **Lattice (Module-SIS/LWE) commitment + lattice range argument — CANDIDATE, not selected.** Retains
   an additive homomorphism (structurally closest to today's proof) and can be perfectly/statistically
   hiding; binding reduces to Module-SIS (PQ). **But** heavier, with concrete-security parameters still
   moving and a larger, less-settled audit surface. The more *feature-preserving* but *less mature*
   option.
4. **"PQ commitment alone, keep the classical Fiat–Shamir proof transform as-is" — REJECTED as
   sufficient.** PQ binding of the commitment is **necessary but not sufficient**: without a QROM
   analysis of the proof transform, end-to-end PQ soundness is **unproven** (item d). Any migration
   must carry the proof system, not just the commitment.
5. **Re-commit with a SNARK-friendly stack (Poseidon + a pairing/SNARK curve) — REJECTED.** Pairing-
   and dlog-based SNARKs are themselves **classically-broken-by-Shor** (not PQ-sound), and add a
   newer, less-audited hash — moving *away* from the PQ goal. (ADR-0013 already rejected SNARK-curve
   re-commitment for the equality problem on adjacent grounds.)
6. **Adopt a specific named primitive now (pin the choice) — REJECTED / PREMATURE.** No standardized,
   audited PQ commitment-with-efficient-range-proof exists to adopt today; pinning one now would
   front-run standardization and the audit. Selection is deliberately deferred (the decision criterion
   in (a) governs it).

## Consequences

- **Positive (intended, post-gate).** Moves the *last classical link* — the commitment's binding and
  the proof's soundness — toward PQ, so the compliance verdict's *integrity* could become PQ
  end-to-end, matching the already-PQ secrecy (Pedersen/info-theoretic) and already-PQ envelope
  (SHA3 binding + ML-DSA-87 + RFC 6962). Raises the audit bar from a bespoke classical proof to a
  standardized PQ primitive + an explicit binding/QROM argument. Reuses ADR-0018's `amount.domain`
  discriminator so it lands with **no new schema break**.
- **Cost / caveats.** A new commitment primitive **and** a new proof system are the largest new audit
  surface in the disclosure stack; PQ proofs/commitments are typically **larger and slower** than the
  ristretto255 construction (size/latency trade-off the audit must size). A **hash-based** choice
  **downgrades hiding from perfect to computational** — an explicit trade the threat model must
  accept; a **lattice** choice keeps strong hiding but is heavier and parameter-unsettled.
- **Residual, explicitly UNPROVEN.** Proof **quantum soundness is ROM-only today and UNPROVEN in the
  QROM** even after the commitment migrates (item d) — the proof transform must be QROM-analyzed.
  Primitive concrete-security parameters are **not pinned**. No primitive is **selected**. Structural
  binding still does **not** defend against a malicious *admitter* (quorum/attestation model's job,
  unchanged). Everything remains **UNAUDITED** and pre-FTO.
- **Sequencing.** This ADR is **strictly downstream** of ADR-0016 (pin `H` — relevant only to the
  *classical* path it eventually retires), ADR-0013 (structural binding — preserved), and ADR-0018
  (canonical `u64` domain + additive v:2 body + the `amount.domain` discriminator this migration
  rides). It does not block any of them; it consumes their interfaces.

## Honesty / status note

This ADR is a **research-track design-direction record**, *not* a security result. The construction
is **unimplemented**, **unaudited**, the primitive is **unselected**, and the whole migration is
**gated behind external audit + primitive standardization** with implementation **deferred**. The
amount's **confidentiality** is already information-theoretic/PQ under Pedersen and stays at least
computationally PQ; the v:2 **SHA3 binding** (ADR-0013/0018) and the ML-DSA-87 / RFC 6962 **envelope**
are already PQ and are **preserved unchanged**; the proof's **soundness** is classical today and would
become PQ **only** with a PQ-binding commitment **and** a **QROM-analyzed** proof transform — the
latter **UNPROVEN**. No production-privacy, soundness, "audited," "production-ready," FIPS, or
non-infringement claim is made or implied. © TRELYAN.

## References

- `docs/STATUS.md` — the "Top forward upgrade (Team Apex deep audit, 2026-06-20)" line this ADR
  formalizes: migrate the commitment layer to a PQ scheme preserving the v:2 SHA3 binding; PSP
  soundness classical/transitional; ZK is ROM-only, not QROM. See `docs/ASSURANCE.md`.
- `disclosure/src/zkrange.ts:27-37, 70-81` — ristretto255 Pedersen `commit(v, r) = v·G + r·H`,
  generators `G`/`H`, `shiftCommitment` homomorphism, scalar order `L`, the `n ≤ 251` cap.
- `disclosure/src/policyproof.ts:27-49` — the PQ-profile / linkage-contract docblock: hiding is
  information-theoretic/PQ, proof soundness is classical (dlog), zero-knowledge is **ROM-only, not
  QROM** (the UNPROVEN quantum-ZK note this ADR carries forward).
- `disclosure/src/commitbind.ts` — `boundIntentDigest` (hashes `commitment.toBytes()`), CB-001
  (amount excluded from the public digest preimage), `verifyBoundAmount`; the SHA3 binding preserved
  here.
- ADR-0006 — Zero-Knowledge Policy-Satisfaction Receipts (the PSP; classical soundness; `psr`).
- ADR-0013 — v:2 structural commitment-to-intent binding (Pedersen ↔ SHA3); the binding this
  migration preserves.
- ADR-0016 — Pin the Pedersen generator `H` provenance + fail-closed invariants (classical-path
  hardening; binding's single root assumption).
- ADR-0018 — Canonical `u64` amount domain + additive v:2 `ReceiptBody`; defines the `amount.domain`
  discriminator (`"u64"` → `"u64/pq"`) this migration reuses with no further schema break.
- ADR-0014 — Salted / hiding v:1 intent commitment; the hide-low-entropy-`v`-behind-high-entropy-`r`
  pattern a hash-based PQ commitment would reuse.
