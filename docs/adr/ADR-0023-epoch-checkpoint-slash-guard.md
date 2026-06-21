<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0023 — Epoch / finalized-checkpoint guard against long-range & stale-evidence slashing

**Status: PROPOSED — DESIGN ONLY, UNIMPLEMENTED.** No code, KAT, or behavior change ships with this
ADR. It records a design decision and routes the construction to external audit / council review before
any implementation. Like the rest of the P4 ledger this is an **internal-review-level, UNAUDITED**
design — it makes **no** proven-secure, audited, non-infringement, or FIPS claim. Date: 2026-06-21.
Track-B item **B8** of the Team Apex sprint backlog
([docs/APEX_SPRINT_BACKLOG.md](../APEX_SPRINT_BACKLOG.md) row B8).

**Composes with ADR-0020 (B5 — validator-set id/epoch binding).** B5 folds a `setId`/`epoch` into the
attestation / timeout-vote / equivocation-proof preimages so consent cannot be transferred across
epochs. This ADR (B8) builds **on top of** that binding: B5 makes evidence *attributable to an epoch*;
B8 decides *which epochs' evidence is still admissible for slashing*. B8 assumes B5's epoch-bound
`EquivocationProof` as its substrate and is **sequenced after** it. If B5 lands with a different field
name/shape than assumed here, the council reconciles at implementation time.

## Context

`ledger/src/equivocation.ts` implements Casper-style accountable-safety slashing:

- `EquivocationProof { validator, height, blockHashA, blockHashB, attA, attB }` — two same-height
  attestations to **distinct** block hashes by one validator.
- `verifyEquivocationProof(proof, set)` accepts the proof iff: the two block hashes differ, both
  attestations name `proof.validator`, the attestations' `blockHash` fields match the claimed hashes,
  **both attestations share one height** (`attA.height === attB.height`, the LEDGER-EQUIV-001 fix that
  prevents two honest cross-height attestations being forged into an "equivocation"), `proof.height`
  equals that height, the validator has positive stake **in the set passed in** (`stakeOf(set, …) > 0`),
  and both ML-DSA signatures verify (`safeVerifyAtt`).
- `slash(set, validators)` returns a new `ValidatorSet` with the named validators removed (stake
  forfeit).

The attestation message (`chain.ts` `attestMessage(suite, height, hash)`) binds suite + **height** +
block hash. **It does not bind an epoch, a validator-set identity, or any time/finality anchor** (ADR-0020 /
B5 adds the epoch binding; this ADR depends on it). Consequently the slashing check is **purely a
function of cryptographic well-formedness plus the *current* set membership** — it has **no notion of how
old the evidence is**.

### Problem: stale / long-range evidence can slash

The threat model already names this class — `docs/THREAT_MODEL.md` lists **T-P3-3** ("long-range /
nothing-at-stake … weak-subjectivity bootstrapping") with mitigation **M-P3-3** ("document
weak-subjectivity checkpoints"). The slashing path is where it bites:

1. **Long-range attack on rotated-out / past validators.** In PoS, a validator's signing key has value
   long after the validator has unbonded and exited the set. An attacker who acquires **old keys**
   (purchased, leaked, or from validators with nothing left at stake) can fabricate two conflicting
   same-height attestations for a **long-past height/epoch**. Today such a proof is *cryptographically
   valid forever*. Whether it slashes depends only on whether `stakeOf(set, validator) > 0` in whatever
   set is passed to `verifyEquivocationProof` — which is brittle: an out-of-band caller that passes a
   *historical* set, or a future design that retains exited validators with residual stake, would slash
   on ancient evidence.

2. **Griefing of rotated-out validators.** Even when the current set check rejects an exited validator,
   the **absence of an admissibility window** means there is no principled, in-protocol statement of
   *when evidence expires*. An honest validator that rotated out cannot rely on a finite liability
   horizon; evidence manufactured against their old key is "valid" indefinitely, which is exactly the
   accountability-inversion the LEDGER-EQUIV-001 height check was added to avoid — here along the **time**
   axis rather than the **height** axis.

3. **Stale-evidence replay across a reorg/bootstrap.** A newly syncing node (or a light client) has no
   trustless way to date an `EquivocationProof`. Without a **finalized-checkpoint floor**, a node booting
   from a weak-subjectivity checkpoint could be fed evidence from *before* that checkpoint and act on it,
   re-litigating already-finalized history — the canonical long-range hook.

The common root cause: **slashing is unbounded in time.** Accountable safety needs the *opposite* of the
LEDGER-EQUIV-001 fix's spirit applied to time — evidence must be **fresh enough** (within an unbonding /
weak-subjectivity window) **and** **above a finalized floor** to be actionable.

## Decision

Introduce two time/finality bounds on slashing, layered on B5's epoch binding. **Design only;
implementation deferred to council.**

### 1. Epoch-bound the `EquivocationProof` (on top of ADR-0020 / B5)

Assume B5 has already bound an `epoch` (and `setId`) into the attestation preimage and surfaced it on the
proof. B8 makes the epoch a **first-class, checked** field of slashing:

```
EquivocationProof {
  validator, height,
  epoch,                       // the epoch the two attestations were signed under (from B5 binding)
  blockHashA, blockHashB, attA, attB
}
```

- `verifyEquivocationProof` additionally requires `attA.epoch === attB.epoch === proof.epoch` (mirroring
  the existing same-height `attA.height === attB.height === proof.height` invariant). Because B5 folds the
  epoch into the **signed** preimage, a forged epoch fails signature verification — the verifier cannot be
  tricked into mislabeling evidence's epoch.
- An equivocation is, by construction, two signatures **within one epoch at one height**. Cross-epoch
  "equivocation" is not equivocation (an honest validator signs different blocks in different epochs),
  exactly paralleling the cross-height case.

### 2. Unbonding / weak-subjectivity admissibility window

Slashing is accepted **only if the proof's epoch is within the unbonding window relative to the current
epoch**:

```
currentEpoch - proof.epoch <= UNBONDING_EPOCHS        // and proof.epoch <= currentEpoch
```

- `UNBONDING_EPOCHS` is a protocol parameter (the weak-subjectivity / unbonding period). Its value is
  **deployment policy**, to be set by the council with the validator economics; this ADR does **not** fix
  a number.
- Rationale: a validator's stake is only at risk while it is bonded plus the unbonding tail. Once a
  validator has been unbonded longer than the window, its old keys carry **no slashable stake**, so
  evidence against them is economically meaningless and admitting it only enables griefing / long-range
  manufacturing. This is the standard PoS weak-subjectivity assumption made explicit in-protocol.
- This is **necessary but not sufficient** on its own — it bounds *recency* but a node still needs a
  trustless *floor* (next item) so it cannot be fed pre-checkpoint evidence while believing it is recent.

### 3. Finalized-checkpoint floor

Maintain a monotonic **finalized checkpoint** `(checkpointEpoch, checkpointHeight)` — the latest epoch
the node treats as irreversibly final (the weak-subjectivity checkpoint a fresh node boots from; an
existing node advances it as the ledger finalizes). Reject any proof **below the floor**:

```
proof.epoch >= checkpointEpoch                        // evidence at/after the last finalized checkpoint only
```

- Evidence strictly *below* the finalized floor concerns already-finalized, non-reorganizable history and
  is **rejected outright** — there is nothing to slash within settled history, and admitting it is the
  long-range replay vector.
- The floor is what makes the unbonding window **trustless for a syncing node**: combined, evidence must
  sit in the half-open band `[checkpointEpoch, currentEpoch]` **and** within `UNBONDING_EPOCHS` of
  `currentEpoch`. A node that boots from a recent weak-subjectivity checkpoint cannot be slashed-by-proxy
  on ancient evidence because such evidence is below its floor.
- The floor must be **monotonic non-decreasing** (it only advances on finalization), so it is itself not
  a grinding surface.

### Composite admissibility predicate

```
slashAdmissible(proof, currentEpoch, checkpointEpoch) :=
      verifyEquivocationProof(proof, set)             // existing crypto + same-height + same-epoch (B5+§1)
   && proof.epoch >= checkpointEpoch                  // §3 finalized-checkpoint floor
   && proof.epoch <= currentEpoch                     // not from the future
   && (currentEpoch - proof.epoch) <= UNBONDING_EPOCHS // §2 unbonding / weak-subjectivity window
```

`slash()` is only invoked on a proof that satisfies `slashAdmissible`. The existing positive-stake check
(`stakeOf(set, validator) > 0`) stays as a final guard against slashing a validator with no current
stake; the new bounds make the *temporal* admissibility explicit rather than relying on set-membership
coincidence.

## Soundness / Security argument (informal, UNAUDITED)

The argument is at the **protocol-logic** level, not a formal proof, and inherits the project's
unaudited status.

- **No safety regression.** The new predicate is a **conjunction added to** the existing checks — it can
  only make `verifyEquivocationProof`/slashing **more** restrictive (reject more), never accept a proof
  the current code rejects. A within-window, above-floor, same-epoch double-sign still verifies and
  slashes exactly as today. Accountable safety (finalizing two conflicting blocks at one height in the
  *current* epoch exposes ≥1/3 stake as slashable) is therefore preserved for the live window, which is
  the window in which the ≥2/3 finality guarantee operates.
- **Long-range / stale evidence is closed (within the stated assumptions).** Evidence below the finalized
  floor is rejected (§3); evidence older than the unbonding tail is rejected (§2). An attacker holding
  *exited* validators' old keys can no longer manufacture a slash, because either the epoch is below a
  syncing node's floor or the bonded stake has unbonded past the window. This is the standard
  weak-subjectivity defense; B8 makes it an explicit in-protocol check rather than an undocumented
  assumption.
- **Griefing of rotated-out validators is bounded.** A validator that has been unbonded for longer than
  `UNBONDING_EPOCHS` has a **finite, known liability horizon**: after it, no proof against its old key is
  admissible. This is the time-axis analogue of the LEDGER-EQUIV-001 height-axis fix.
- **Forged epoch labels are infeasible** *given B5*: the epoch is in the signed attestation preimage, so
  `safeVerifyAtt` already rejects a relabeled epoch. **This security rests entirely on ADR-0020/B5 being
  implemented as assumed** — if the epoch is *not* signature-bound, §1's epoch equality check is forgeable
  and the whole guard degrades. This dependency is a **binding residual assumption**, flagged below.

### Residual assumptions & honest limits (binding)

- **Depends on ADR-0020 / B5.** The epoch must be **signed into** the attestation preimage. B8 is unsound
  if layered on an unsigned/derived epoch. Sequence B5 → B8.
- **Weak-subjectivity is a trust assumption, not a cryptographic guarantee.** The finalized-checkpoint
  floor assumes the node obtained an **honest** recent checkpoint out-of-band (the canonical PoS
  weak-subjectivity premise). A node that boots from a *malicious* checkpoint is outside this model — the
  guard cannot fix a poisoned trust root, only make the dependency explicit. This is documented, not
  eliminated.
- **`currentEpoch` provenance.** The window check needs a trustworthy notion of "now" (the current
  epoch). For an online node this is the finalized chain tip; for a light client it must come from the
  same verified-finality path, **not** from the (untrusted) proof submitter. Getting this wrong
  reintroduces the attack; the council must pin the source of `currentEpoch` at implementation.
- **Parameter choice is economics, not crypto.** `UNBONDING_EPOCHS` trades griefing-resistance (smaller)
  against catching genuinely-delayed evidence (larger). Out of scope here; set with validator economics.
- **Crypto assumptions unchanged.** ML-DSA-87 (FIPS 204) for attestation signatures; classical security
  notes from ADR-0004 (VRF is classical) are unaffected — this ADR adds no new primitive. No ROM/QROM
  argument is introduced because no new commitment/hash construction is added; the only hash use remains
  the existing `attestMessage`/`blockHash` SHA3/SHAKE, whose ROM-vs-QROM posture is inherited unchanged.
- **UNAUDITED.** This records a *design decision*, not a security result. External ROS/ToB audit still
  applies.

## Implementation plan (deferred — what would change, behind which flags)

Sequenced **after** ADR-0020/B5 lands. All changes gated so the new bounds can be rolled out without
breaking existing conformance until the vectors are regenerated.

1. **Type (`ledger/src/types.ts`).** Add `epoch: number` to `EquivocationProof` (consuming B5's
   epoch-bound attestation). If B5 already adds `epoch` to `Attestation`, reuse it; B8 only adds the proof
   field + checks.
2. **Verifier (`ledger/src/equivocation.ts`).**
   - Extend `verifyEquivocationProof` with the same-epoch invariant (`attA.epoch === attB.epoch ===
     proof.epoch`), paralleling the same-height invariant.
   - Add a new admissibility entry point — e.g. `slashAdmissible(proof, set, { currentEpoch,
     checkpointEpoch, unbondingEpochs })` — implementing §2+§3. Keep `verifyEquivocationProof`'s pure
     crypto/well-formedness signature intact (no temporal args) so callers that only need *validity* are
     unchanged; temporal admissibility is the new, separately-callable gate before `slash()`.
   - `slash()` itself is unchanged (it already just removes named validators); the guard sits *before* it.
3. **Feature flag.** Introduce an options flag (e.g. `enforceSlashWindow`, default **off** until vectors
   regen) so enabling the window/floor checks is explicit and reversible during rollout. With the flag
   off, behavior is byte-identical to today.
4. **Parameters.** `UNBONDING_EPOCHS` and the source of `currentEpoch` / `checkpointEpoch` are wired as
   explicit inputs (no hidden globals), so tests and deployments set them deterministically.
5. **KAT / conformance regeneration plan.**
   - Add **negative** vectors to `conformance/vectors/ps-negative.json`: (a) a well-formed proof with
     `proof.epoch < checkpointEpoch` → rejected (floor); (b) a proof with `currentEpoch - proof.epoch >
     UNBONDING_EPOCHS` → rejected (window); (c) a proof with `attA.epoch !== attB.epoch` → rejected
     (same-epoch invariant); (d) a future-epoch proof (`proof.epoch > currentEpoch`) → rejected.
   - Add **positive** vectors: a within-window, above-floor, same-epoch double-sign → admissible +
     slashes (parity with today).
   - Regenerate the deterministic KAT (`crypto/vectors/deterministic-kat.json` /
     `conformance/vectors/ps-kat.json`) only if B5's epoch binding changed the attestation preimage; B8
     alone adds no new signed bytes (it checks an already-signed field), so **no new signing KAT is
     required for B8 in isolation** — the regen is B5's. A new **conformance check** (next free C-number,
     to be assigned at merge) asserts the four negative cases + the positive case above.
   - Update `ledger/test/equivocation.test.ts` with window/floor/same-epoch cases.
6. **Docs.** Update `docs/THREAT_MODEL.md` M-P3-3 from "*document* weak-subjectivity checkpoints" to
   "*enforced* unbonding window + finalized-checkpoint floor in slashing (ADR-0023)", and note the B5→B8
   dependency. Update any STATUS/ASSURANCE row covering LEDGER-006 slashing.

## Alternatives considered

1. **Bind a timestamp / wall-clock window instead of an epoch — REJECTED.** Block timestamps are
   proposer-influenced and not trustless; epochs are the chain's own monotonic, finality-anchored unit and
   already the binding B5 introduces. Reusing the epoch keeps one source of truth.
2. **Finalized-checkpoint floor only, no unbonding window — REJECTED (insufficient).** The floor stops
   *pre-checkpoint* replay but does nothing to bound the liability horizon of a validator that unbonded
   *after* the checkpoint; griefing of recently-rotated-out validators would remain. The window is the
   piece that gives a finite, known liability horizon.
3. **Unbonding window only, no floor — REJECTED (insufficient & not trustless on sync).** Without a floor,
   a freshly-syncing node has no trustless "now" anchor and could be fed evidence it mis-dates as recent.
   The floor is what makes the window safe for bootstrapping nodes/light clients.
4. **Slash-then-revert with a challenge period — REJECTED for now.** A latency-based optimistic scheme
   (slash, allow a window to dispute) adds liveness/UX complexity and a new griefing surface (spurious
   slashes reverted later) without removing the need for an admissibility bound. The conjunctive
   admissibility predicate is simpler and strictly defensive.
5. **Keep relying on the current-set `stakeOf > 0` check alone — REJECTED.** It conflates "is currently
   bonded" with "evidence is fresh," is brittle to which set the caller passes, and gives no in-protocol
   statement of evidence expiry. It is retained as a *final* guard but is not a substitute for explicit
   temporal bounds.

## Consequences

- **Strictly more restrictive slashing** (a conjunction of new checks) — no path is newly *accepted*, so
  there is no safety regression for the live window; the cost is that genuinely-delayed evidence older
  than `UNBONDING_EPOCHS` (or below the floor) becomes inadmissible, which is the intended
  weak-subjectivity trade-off.
- **Finite, documented validator liability horizon** — rotated-out validators gain a known expiry on
  slashing liability, closing the time-axis griefing/inversion analogue of LEDGER-EQUIV-001.
- **Explicit weak-subjectivity dependency** — the design surfaces, rather than hides, the trust in an
  honest recent checkpoint and in a trustworthy `currentEpoch` source; deployments must satisfy these.
- **Hard ordering dependency on ADR-0020/B5** — B8 must not be implemented before B5's signature-bound
  epoch exists, or the epoch checks are forgeable.
- **No code/KAT/behavior change in this ADR** — proposal only; routes to council/external audit. The
  conformance/KAT plan above is the *intended* regen, executed only when the design is implemented.

## References

- `ledger/src/equivocation.ts` — `EquivocationProof`, `verifyEquivocationProof`, `slash`, and the
  LEDGER-EQUIV-001 same-height invariant.
- `ledger/src/chain.ts` — `attestMessage` (suite + height + hash preimage), `verifyFinalized`,
  `verifyAttestationSig`; LEDGER-006 "equivocation slashing deferred" note.
- `ledger/src/types.ts` — `Attestation`, `EquivocationProof` substrate; `ValidatorSet`.
- [ADR-0004](ADR-0004-vrf-sortition.md) — VRF sortition + accountable-safety framing (classical-VRF /
  PQ-signature hybrid; safety is PQ, liveness/unpredictability classical).
- **ADR-0020 (B5)** — validator-set id/epoch binding folded into attestation / timeout-vote /
  equivocation-proof preimages (the epoch substrate B8 depends on; ADR number per the B5 branch).
- [docs/THREAT_MODEL.md](../THREAT_MODEL.md) — **T-P3-3** (long-range / nothing-at-stake /
  weak-subjectivity) and **M-P3-3** (document weak-subjectivity checkpoints) — this ADR enforces M-P3-3.
- [docs/APEX_SPRINT_BACKLOG.md](../APEX_SPRINT_BACKLOG.md) — Track-B row **B8**.
