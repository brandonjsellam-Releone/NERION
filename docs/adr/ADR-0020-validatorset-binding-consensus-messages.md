<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0020 — Bind validator-set id + epoch into consensus messages (view-change votes, attestations, equivocation proofs)

**Status: IMPLEMENTED (as-built variant) — 2026-06-28.** The cross-epoch consent-transfer hole is
now closed in code (Team Apex max-hardening sweep). The shipped design is a **simplification** of the
preimage spec below — see **As-built** immediately after this banner for the exact divergence. Still
**UNAUDITED**; makes **no** proven / non-infringement / FIPS claim; rests on the residual assumptions
in **Trust model / limits** (epoch authenticity is still the finalized-chain's job). Original design
date 2026-06-21, Track-B item **B5**; mirrors the implemented ADR-0005 (quorum-receipt set-binding).

## As-built (2026-06-28) — how the shipped code differs from the proposed preimage

The security property (a signature binds the exact `(members, stake, vrfPubkey, epoch)` it was made
under, recompute-and-compare at verify) is delivered exactly as argued. The implementation chose the
**lower-churn** shape:

- **`epoch` lives on `ValidatorSet`** (`ledger/src/types.ts`, optional, default `0`) — not as a
  separate `Ledger` constructor param nor a wire field on `Attestation`/`TimeoutVote`/
  `EquivocationProof`. `consensusSetId(set)` folds `set.epoch ?? 0` into the id.
- **The signed preimage binds `setId` only** (epoch is _inside_ `setId`), not `setId` + a separate
  explicit `epoch` field:
  `attestMessage = ['polarseek-attest-v2', suite, height, hash, setId]`;
  `viewChangeMessage = ['polarseek-timeout-v2', suite, height, prevHash, round, setId]`.
  (The "belt-and-suspenders" explicit-epoch field from §2 was dropped as redundant — `setId`
  collision-resistantly commits the epoch already.)
- **Verifiers derive `setId` from their own `set`** (`consensusSetId(set)`) — no new `epoch`
  parameter is threaded; `verifyEquivocationProof(proof, set)` keeps its signature and derives the
  id internally. A cross-set/epoch signature reconstructs to a different preimage and fails
  `safeVerify` (contributes zero stake / rejects the proof) — Attacks A/B/C all closed by the same
  comparison.
- **`consensusSetId`** is exported from `ledger/src/index.ts`; helper in `sortition.ts`.
- **Regression coverage** is in the ledger unit suite (a same-members/different-epoch bundle is
  finalized under epoch 0 but NOT under epoch 1 — `ledger/test/chain.test.ts`; all timeout-vote tests
  bind `consensusSetId`). Equivocation slashing is now **epoch-scoped** (a stale cross-epoch proof is
  rejected — Attack C closed in the "reject" direction).
- **Conformance C24 ADDED (2026-07-08).** `conformance/src/suite.ts` now asserts the property
  end-to-end via the public API: a same-members/different-epoch attestation bundle finalizes under
  its own epoch's `verifyFinalized` and is rejected under a different epoch's — count lifted **23 →
  24**; every "23-of-23" cross-reference (README/STATUS/ASSURANCE/THREAT_MODEL/gov+grants docs and the
  memory index) updated in the same commit, per this ADR's own §5 instruction.
- **Still a follow-up (NOT done):** the `ps-kat.json` consensus vectors from the Implementation-plan
  §5 (byte-exact `consensusSetId` / `attestMessage` / `viewChangeMessage` fixtures for a fixed toy set
  - epoch) are not yet added — C24 is conformance-level (asserts the property via the public API), not
    yet a frozen byte-exact KAT vector. The TLA⁺ accountable-safety model is **not** extended to a
    multi-epoch dimension (single-epoch model remains valid; the binding is additive).

## Context

`receipts/src/quorum.ts` already binds a quorum receipt to the exact validator set it was issued
under: it commits `setId = SHAKE256(canonical([ctx, sorted [pubkey,stake], k, epoch]))` into the
signed body and the verifier **recomputes** `setId` from its own trusted (finalized) `ValidatorSet`,
rejecting on mismatch (ADR-0005). `governance/src/quorum.ts` carries the analogous `quorumId`
binding for committee approvals (GOV-QUORUM-001). The **consensus-layer messages in `ledger/`,
however, do NOT bind the validator set or the epoch.** Their signed preimages are:

| Message                    | Builder / verifier                           | Signed preimage today (`ledger/src`)                       |
| -------------------------- | -------------------------------------------- | ---------------------------------------------------------- |
| Attestation                | `attestMessage` (`chain.ts`)                 | `['polarseek-attest-v1', suite, height, hash]`             |
| View-change (timeout) vote | `viewChangeMessage` (`leader.ts`)            | `['polarseek-timeout-v1', suite, height, prevHash, round]` |
| Equivocation proof         | wraps two `Attestation`s (`equivocation.ts`) | (no preimage of its own — inherits the attestation's)      |

None of these three carries the validator-set identity or an epoch. The proposer block-signature
preimage (`blockSignMessage`) and the block header are likewise set-agnostic, but the three messages
above are the consent-bearing votes whose reuse transfers consent, so they are the scope of B5.

**The gap — cross-epoch consent transfer.** A validator's signature over an attestation or a
timeout vote is valid for _any_ `ValidatorSet` and _any_ epoch that happens to present the same
`(suite, height, hash)` / `(suite, height, prevHash, round)` tuple. Because the verifier never
checks which set/epoch the signature was made under, a signature gathered in one epoch can be
**replayed into another**:

- **Attack A — finality forgery across an epoch boundary.** Stake is reweighted, validators
  rotate in/out, or slashing changes the set between epoch _e_ and _e+1_. Heights and block hashes
  are not globally unique across epochs (a fork/replay or a re-org can re-present a height; a
  light client bootstrapping a different epoch can be fed an old `(height, hash)`). Honest
  attestations collected under epoch _e_ — where their signers _were_ high-stake validators — are
  re-presented to a verifier operating under the epoch-_e+1_ set, where those same keys may carry
  different (or zero, if slashed/rotated-out) stake. `verifyFinalized` counts them by the _current_
  set's stake but never checks they were signed _for_ this set, so consent minted for one
  validator-set configuration is **transferred** to another. Combined with a substituted/permissive
  set at verification time (the ADR-0005 threat, here unguarded), this lets an attacker assemble a
  "finalized" block under a configuration the signers never consented to.
- **Attack B — view-change vote replay across epochs.** A `TimeoutVote` for `(height, prevHash,
round)` made in epoch _e_ is re-counted in epoch _e+1_ (same height/prevHash after a re-org, or a
  deliberately reconstructed view) to manufacture a ≥2/3 view-change certificate and force a round
  skip / re-draw the VRF leader among an epoch the voters never timed out in — without any voter
  acting in the new epoch.
- **Attack C — stale equivocation slashing across epochs.** `verifyEquivocationProof` already
  requires _same-height_ double-signing (LEDGER-EQUIV-001) and that the validator has positive
  stake in the supplied set. But the two attestations are not bound to an epoch, so an equivocation
  that occurred in epoch _e_ can be submitted against the epoch-_e+1_ set to slash a validator whose
  epoch-_e+1_ identity/stake should not be answerable for an epoch-_e_ fault (or, symmetrically, to
  _evade_ slashing by presenting the proof against a set where the offender's stake reads zero). The
  proof carries no epoch to pin which set it is accountable under.

This is the same _consent-transfer / set-substitution_ class ADR-0005 closed for receipts and
GOV-QUORUM-001 closed for governance, now identified at the consensus layer (Track-B B5). The
existing per-message hardening — suite binding, height binding, BigInt-exact thresholds,
distinct-signer dedupe — does **not** address it, because all of those quantities can recur
unchanged across epochs.

## Decision

Define a single consensus **validator-set id** and **fold it, plus an explicit `epoch`, into the
three signed preimages**, mirroring `quorumSetId`. Verification recomputes the id from the verifier's
own trusted set/epoch and rejects on mismatch — so a signature made under one set/epoch cannot be
counted under another.

### 1. The consensus set id

```
CONSENSUS_CTX = "polarseek-consensus-set-v1"

consensusSetId(set: ValidatorSet, epoch: number): string
  = SHAKE256(encodeCanonical([
      CONSENSUS_CTX,
      sorted_by_pubkey([ (v.pubkey, v.stake, v.vrfPubkey ?? '') for v in set.validators ]),
      epoch,
    ]))            // full-length hex, NO truncation (per GOV-QID-001)
```

- Sorting by `pubkey` makes it order-independent (mirrors `quorumSetId` / `vrfLeaderEligible`).
- `stake` is included so a **reweighted** set is a _different_ set (mirrors ADR-0005).
- `vrfPubkey` is included because the ledger's leader eligibility is keyed off it (ADR-0004); a set
  that swaps a validator's VRF key is a different consensus configuration and must not share an id.
  (This is the one field beyond the `quorumSetId` preimage — justified by the consensus layer's VRF
  dependency. `quorumSetId` binds `k`; consensus messages have no fixed `k`, so `k` is **not** in
  this id — the finality fraction is a verifier parameter, not a set property.)
- No threshold is folded in: attestation finality is `≥ finalityNum/finalityDen` of _total stake_,
  which is already pinned because total stake is a function of the bound `(pubkey, stake)` list.

### 2. Preimage changes (the three messages)

Each tag is bumped to a `-v2` domain tag so a v2 verifier can never accept a v1 signature as if it
were set-bound, and vice-versa (no silent cross-version confusion):

```
// chain.ts — attestation
attestMessageV2(suite, setId, epoch, height, hash)
  = encodeCanonical(['polarseek-attest-v2', suite, setId, epoch, height, hash])

// leader.ts — view-change / timeout vote
viewChangeMessageV2(suite, setId, epoch, height, prevHash, round)
  = encodeCanonical(['polarseek-timeout-v2', suite, setId, epoch, height, prevHash, round])
```

`setId = consensusSetId(set, epoch)`. The `epoch` appears **both** inside `setId` and as an explicit
field; this is intentional belt-and-suspenders so a mismatch is legible to a verifier that wants to
report "wrong epoch" distinctly from "wrong set," exactly as ADR-0005 commits `epoch` both inside
`setId` and as `quorum.epoch`.

The `Attestation` and `TimeoutVote` interfaces (`ledger/src/types.ts`) gain a committed
`epoch: number` (and the messages recompute `setId` from the verifier's set — `setId` itself need
not be stored on the wire, it is recomputed, exactly as `verifyQuorumReceipt` recomputes it; storing
`epoch` is enough). For the **equivocation proof**, bind the epoch directly:

```
interface EquivocationProof { ..., epoch: number }   // new field
```

Both inner attestations must already carry the same `epoch` (they are `attestMessageV2`-signed under
it), and the proof's top-level `epoch` must equal both — so a proof is accountable under exactly one
named epoch/set.

### 3. Verification changes

All verifiers take the trusted `epoch` as an explicit parameter (as `verifyQuorumReceipt(set, k,
epoch)` already does) and recompute `setId = consensusSetId(set, epoch)`:

- **`verifyFinalized` / `verifyAttestationSig` (`chain.ts`)** — recompute the per-attestation
  preimage with `attestMessageV2(a.suite, setId, epoch, height, hash)`. An attestation whose
  committed `epoch` ≠ the verifier's `epoch` is **not counted** (same `continue`-skip discipline as
  the existing height/suite filters), and one whose signature was made for a different `setId`
  fails `safeVerify` and is not counted. Fail-closed: an attestation that does not bind _this_
  set/epoch contributes zero stake.
- **`verifyViewChangeCert` (`leader.ts`)** — recompute `viewChangeMessageV2(..., setId, epoch, ...)`;
  votes not bound to the trusted set/epoch are skipped, so a sub-set/cross-epoch certificate cannot
  reach the BigInt-exact ≥2/3 threshold.
- **`verifyEquivocationProof` (`equivocation.ts`)** — add `epoch` as a parameter; require
  `proof.epoch === proof.attA.epoch === proof.attB.epoch === epoch`, recompute both inner
  attestation preimages under `attestMessageV2(..., consensusSetId(set, epoch), epoch, ...)`, and
  keep the existing same-height + positive-stake + `safeVerifyAtt` checks. A proof not bound to the
  set/epoch it is being judged under is rejected (no cross-epoch slash, no cross-epoch evasion).

The `Ledger` class threads its `epoch` (a new constructor field, defaulting to `0` for the existing
single-epoch tests) into `attest` / `propose*` / `submit` so produced messages are bound and
`appraise` verifies under the same epoch.

### Why this shape (mirrors ADR-0005, not a new primitive)

Zero new cryptographic primitives: pure composition of the already-used SHAKE256 + deterministic
CBOR + ML-DSA-87 over a domain-separated preimage. The defense is **recompute-and-compare** at
verification time — the _same_ mechanism that makes ADR-0005 load-bearing — lifted to the consensus
votes. Safety stays fully post-quantum (ML-DSA-87 EUF-CMA); no classical assumption is added beyond
the ed25519 VRF that ADR-0004 already owns.

## Soundness / security argument (informal, UNAUDITED)

Let _H_ = SHAKE256 modeled as a collision/2nd-preimage-resistant hash, and assume ML-DSA-87 is
EUF-CMA. A signature counted by a v2 verifier under trusted `(set, epoch)` is a valid ML-DSA-87
signature over a message containing `consensusSetId(set, epoch)`.

- **Closes Attack A/B (cross-epoch reuse).** A signature minted under `(set', epoch')` commits
  `consensusSetId(set', epoch')`. For it to be counted under `(set, epoch)` the verifier must
  recompute the _same_ preimage, which requires `consensusSetId(set, epoch) =
consensusSetId(set', epoch')`. By collision-resistance of _H_ over an injective canonical encoding,
  that holds only if the sorted `(pubkey, stake, vrfPubkey)` list **and** `epoch` are identical —
  i.e. it is literally the same configuration. So consent minted for one set/epoch cannot be counted
  for a different one; an attacker cannot make an old-epoch attestation/vote count under a new epoch
  without forging ML-DSA-87 (contradiction) or finding an _H_ collision (contradiction).
- **Closes Attack C (stale slashing).** The equivocation proof and both inner attestations are
  pinned to one `epoch`; judged under any other epoch they are rejected, so a fault is slashable only
  under the set/epoch it was committed in.
- **Composes with ADR-0005's substitution defense.** Even a verifier fed a permissive/substituted
  set cannot benefit: the recomputed `setId` then reflects the _attacker's_ set, so honestly-signed
  attestations (bound to the _real_ set's id) no longer match and are not counted — substitution and
  cross-epoch reuse are closed by the same comparison.

**This is an argument, not a proof.** It is informal, in the random-oracle idealization of SHAKE256,
and **not externally audited**. See limits below.

## Implementation plan (original pre-as-built proposal; superseded by the As-built section above)

> **Superseded (2026-07-08).** The binding itself landed as the simpler **as-built variant** described
> at the top of this ADR (no `epoch` wire field, no `V2`-suffixed function names, no migration flag —
> `epoch` lives on `ValidatorSet` and rides inside `setId`). §5's conformance item is now DONE (C24,
> via the public `verifyFinalized` API, count 24/24); its KAT-vector sub-item remains open. The
> numbered plan below is preserved as the historical record of the original (heavier) design; it was
> not built as specified.

Nothing here is built by this ADR. When council approves implementation:

1. **Crypto/encoding (additive).** Add `consensusSetId`, `attestMessageV2`, `viewChangeMessageV2`
   beside the existing `attestMessage` / `viewChangeMessage` (keep the v1 functions for the
   migration window). Add `epoch` to `Attestation` / `TimeoutVote` / `EquivocationProof`.
2. **Verifier wiring.** Thread `epoch` through `verifyFinalized`, `verifyAttestationSig`,
   `verifyViewChangeCert`, `verifyEquivocationProof`, and the `Ledger` constructor/methods.
3. **Flag / migration.** Gate behind a `LedgerConfig.bindSetEpoch` (or `consensusMsgVersion: 1|2`)
   flag, default **off** initially so the legacy single-epoch path and existing tests are
   unaffected; flip to on (and v2-only) once ported. The v2 domain tags guarantee a v2 verifier
   never accepts a v1 signature, so the two cannot be confused during migration.
4. **Tests.** Regression tests for: (a) an epoch-_e_ attestation/vote not counted under epoch _e+1_;
   (b) a reweighted set (same members) rejected; (c) a swapped `vrfPubkey` rejected; (d) an
   equivocation proof rejected under the wrong epoch; (e) no-regression for the single-epoch
   (`epoch=0`) path.
5. **KAT / conformance regen plan.**
   - **Conformance:** add a new check **C24** ("consensus messages are validator-set/epoch-bound:
     cross-epoch attestation reuse rejected, reweighted-set rejected, equivocation proof epoch-bound")
     to `conformance/src/suite.ts`, lifting the count from 23 to **24**; update every "23-of-23"
     reference (README/STATUS/ASSURANCE and the memory index) to "24-of-24" **in the implementing
     PR, not here**. Mirrors how C12 (ADR-0005) and C23 (ADR-0014) were added.
   - **KAT:** `conformance/vectors/ps-kat.json` currently pins only the deterministic _primitives_
     (hash/mac/aead/sig) — it has **no** consensus-message vectors today, so nothing existing is
     invalidated. The plan adds a new `consensus` section to `tools/gen-kat.mjs` pinning the exact
     bytes of `consensusSetId`, `attestMessageV2`, and `viewChangeMessageV2` for a fixed toy set +
     epoch, then regenerates via `npm run build && npm run kat` and commits the refreshed
     `ps-kat.json` (covered for REUSE by the existing `**/*.json` annotation). The Rust hot-path
     crate inherits these as its byte contract.
   - No _existing_ KAT bytes change (the v1 preimages and all primitive vectors are untouched), so
     this is purely additive — the regen adds vectors, it does not rewrite old ones.

## Alternatives considered

1. **Bind only `epoch` (a bare counter), not the full set id — REJECTED.** An epoch counter alone
   does not detect a _substituted_ set at the same epoch number (the ADR-0005 threat), and couples
   safety to a monotonic counter being assigned honestly. Hashing the actual `(pubkey, stake,
vrfPubkey)` list makes the binding self-certifying: the id _is_ the configuration.
2. **Bind only the set id, not `epoch` — REJECTED.** Two genuinely identical sets can recur across
   epochs (no rotation that round); without `epoch`, a vote is still replayable between them. Folding
   `epoch` in (and committing it explicitly) makes every epoch a distinct domain even for an
   unchanged set.
3. **Per-message random nonces / freshness tokens — REJECTED for this layer.** Nonces need
   distribution + anti-replay state and don't express _which configuration_ consented. The
   recompute-and-compare set id is stateless and verifier-recomputable, matching the rest of the
   stack (no clock, no module state — the property `verifyQuorumReceipt` advertises).
4. **A monotonic cert-chain from epoch 0 (analogous to the LEDGER-007 view-change cert chain) —
   DEFERRED, complementary.** A chain proving epoch transitions is a stronger, separate property
   (it would also pin _order_ of epochs); B5's set/epoch binding is the minimal, surgical close of
   the consent-transfer hole and composes with a future cert-chain rather than competing with it.
5. **Truncate `consensusSetId` to save bytes — REJECTED.** Per GOV-QID-001 the binding id is the
   security anchor; a truncated id invites a birthday-bound cross-configuration collision. Full
   length only.

## Consequences

- **Closes the cross-epoch consent-transfer hole** for the three consensus messages, bringing the
  consensus layer to parity with the receipt (ADR-0005) and governance (GOV-QUORUM-001) bindings.
- **Wire-format / interface change** (gated): `Attestation`, `TimeoutVote`, `EquivocationProof` gain
  `epoch`; the v1↔v2 domain-tag split means a flag-day or dual-accept window per the migration plan.
  This is a **breaking** change to any external attestation producer — hence flagged, gated, and
  council-routed rather than shipped.
- **Additive, no-regression intent:** the `epoch=0` single-epoch path reproduces today's behavior;
  v1 functions stay during migration.
- **Conformance count moves 23 → 24** (new C24) _in the implementing PR_; this ADR does not touch
  any count, test, or vector.
- **FTO still required** before any public claim — design-around is engineering intent, not a legal
  opinion ([FTO_TODO.md](../FTO_TODO.md)). © TRELYAN; Apache-2.0.

## Trust model / limits (honest, binding)

- **UNAUDITED design.** The soundness argument is informal and in the SHAKE256 random-oracle
  idealization; it is **not** a proof and **not** externally audited. No "proven," "audited," "FIPS,"
  or non-infringement claim is made or implied.
- **Residual assumption — epoch authenticity.** This ADR makes a signature _bind_ the epoch/set it
  was made under; it does **not** establish _which_ epoch/set is the canonical current one. The
  verifier's trusted `(set, epoch)` is an input, assumed correct (delivered by the finalized PoS
  chain / the operator's trust root). Authenticating the current epoch is the cert-chain /
  finalized-chain's job (Alternative 4), out of scope for B5.
- **Residual assumption — finalized set is honestly ≥2/3.** Liveness and the meaning of "the trusted
  set" still rest on the underlying PoS finality (≥2/3 honest stake); binding does not change the
  fault model, only forecloses cross-epoch reuse within it.
- **Scope.** Covers the three consent-bearing messages named in B5. The block header / proposer
  signature carry the set only implicitly (via the attestations that finalize them); a separate
  decision could bind the header too, but B5 does not.
- **Liveness vs safety.** As with ADR-0005, this is a _safety_ hardening; it adds no liveness
  assumption and no new classical primitive.

## References

- `receipts/src/quorum.ts` — `quorumSetId` / `verifyQuorumReceipt` (the mirrored pattern); ADR-0005.
- `governance/src/quorum.ts` — `quorumId` set-binding (GOV-QUORUM-001 / GOV-QID-001).
- `ledger/src/chain.ts` — `attestMessage`, `verifyFinalized`, `verifyAttestationSig`.
- `ledger/src/leader.ts` — `viewChangeMessage`, `verifyViewChangeCert`.
- `ledger/src/equivocation.ts` — `EquivocationProof`, `verifyEquivocationProof` (LEDGER-EQUIV-001).
- `ledger/src/types.ts` — `Attestation`, `TimeoutVote`, `ViewChangeCert`, `Validator`.
- `conformance/src/suite.ts` — checks C1–C23 (C12 = ADR-0005 set-binding; C23 = ADR-0014).
- `tools/gen-kat.mjs`, `conformance/vectors/ps-kat.json` — KAT regen target.
- ADR-0004 (VRF sortition + view-change, Proposed), ADR-0005 (quorum receipts, Accepted),
  ADR-0014 (salted intent commitment, Accepted).
- [FTO_TODO.md](../FTO_TODO.md) — freedom-to-operate is required before any public claim.
