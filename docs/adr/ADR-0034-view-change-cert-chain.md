<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0034 — View-Change Certificate Chain to Close the Round-Skip Gap (LEDGER-007)

**Status: PROPOSED — implementation deferred, pending council approval and external audit.**
This ADR is a *design decision record*, not a security result. The construction below is
**UNAUDITED**; the soundness argument is an internal cryptographic sketch with residual assumptions
flagged throughout. **No part of the implementation — no source file, KAT vector, or conformance
behavior — is modified by this ADR.** Nothing here constitutes a proven, audited, production-ready,
FIPS-validated, or non-infringement claim. Routes to: external consensus/crypto audit and Track-B
council approval before any code or KAT change. Date: 2026-06-24. Addresses **LEDGER-007**
(documented in `ledger/src/chain.ts:317–329`, `docs/STATUS.md`, `docs/SECURITY_FINDINGS.md`,
`docs/adr/ADR-0004-vrf-sortition.md`).

---

## 1  Context

### 1.1  Current view-change protocol

The P4 ledger uses VRF-private leader sortition (ADR-0004). When no validator is VRF-eligible for
a round, or when the chosen leader fails to propose within the protocol timeout, validators sign
`TimeoutVote`s and these are aggregated into a `ViewChangeCert` that justifies advancing to the
next round. The current wire types (`ledger/src/types.ts`) are:

```typescript
// ledger/src/types.ts  (current — read-only; ADR/doc-only ADR)
export interface TimeoutVote {
  readonly height:    number
  readonly prevHash:  string   // hex
  readonly round:     number
  readonly validator: string   // hex ML-DSA-87 consensus pubkey
  readonly suite:     string
  readonly sig:       Bytes    // ML-DSA-87 signature over viewChangeMessage(...)
}

export interface ViewChangeCert {
  readonly round: number
  readonly votes: readonly TimeoutVote[]
}
```

The corresponding verifier (`ledger/src/leader.ts:80–122`, `verifyViewChangeCert`) checks:

- Each `TimeoutVote` in the cert carries `(height, prevHash, round)` matching the block's position.
- Each vote is signed with a valid ML-DSA-87 signature under the declared validator's key.
- The counted weight of distinct, suite-matched, valid voters reaches the ≥2/3-stake finality
  threshold (using exact `BigInt` cross-multiplication to prevent floating-point threshold inversion
  — LEDGER-PRECISION-001/-002/-004).
- The verifier is **stateless**: it consults no clock, never throws an exception on bad input, and
  fails closed on every structural abnormality.

A `round > 0` block must carry a `ViewChangeCert` for round `round − 1`; this is checked in both
`proposeVrf` (`ledger/src/chain.ts:152–166`) and `verifyFinalized` (`chain.ts:330–343`).

### 1.2  The LEDGER-007 gap

A round-`r` block proves **only that round `r − 1` timed out** — a single cert — not that rounds
`0, 1, …, r − 1` each timed out in sequence. A coalition controlling ≥2/3 of stake can therefore:

1. Jointly sign a `ViewChangeCert` for an arbitrarily high target round `T − 1` (one signing round,
   one cert object).
2. Immediately propose at round `T`, skipping rounds `1 … T − 1` entirely.

Because the VRF leader is drawn fresh each round (`vrfAlpha(prevHash, round)`,
`ledger/src/leader.ts:26`), skipping rounds lets the coalition **re-roll the VRF leader draw at
zero marginal cost** until a round whose VRF winner is one of their own. The cost of advancing `N`
rounds today is **O(1)**: one quorum-threshold signing ceremony, regardless of `N`.

**Safety is unaffected.** Each block still requires its own independent ≥2/3 attestation set;
accountable-safety and equivocation-slashing (`ledger/src/equivocation.ts`) are orthogonal to
which round won. Round is deliberately omitted from `attestMessage` so all same-height attestations
remain equivocation-comparable (LEDGER-EQUIV-001); this ADR does not touch that invariant.

**Scope of exploitability.** The gap is exploitable only by a coalition that already controls
≥2/3 of stake — i.e. a quorum that already controls liveness. A <1/3 Byzantine actor cannot forge
any cert at all (cannot fabricate a ≥2/3 quorum's signatures), so it cannot skip a single round.
The gap is therefore a **fairness / leader-allocation weakening**, not a safety failure.

**Intended property.** Skipping `N` rounds should cost **O(N)** independent quorum-signing
ceremonies, making VRF-leader re-rolling linearly expensive rather than free. ADR-0004 already
identifies "a cert chain (each cert referencing the prior) is the rigorous fix"; this ADR
formalizes that chain.

---

## 2  Decision

Design a **chained ViewChangeCert structure** in which each cert cryptographically references the
digest of the immediately preceding round's cert, forming a chain anchored at the last finalized
checkpoint (round 0 for the current block height). A correct validator rejects a `ViewChangeCert`
for round `r − 1` that does not present — directly or by reference — a complete, digest-linked
chain `C_0, C_1, …, C_{r−1}` in which every link is independently a valid ≥2/3 cert for its own
round.

Under this rule the cost of skipping `N` rounds is **O(N)** quorum-signed certs. A ≥2/3 coalition
wishing to advance `N` rounds must produce `N` independent quorum-threshold signing ceremonies
(one per intermediate round), removing the ability to re-roll the VRF leader freely.

---

## 3  New cert-chain data structure

### 3.1  Cert digest function

Define a canonical, domain-separated digest over a cert's quorum-relevant content. The preimage
uses the same `encodeCanonical` (dCBOR canonical serialization) and `SHA3_SHAKE256` already used
for `blockHash` in `ledger/src/chain.ts`:

```
certDigest(cert: ChainedViewChangeCert) : hex-string =
  bytesToHex(
    SHA3_SHAKE256.digest(
      encodeCanonical([
        'nerion-viewchange-cert-v1',   // domain tag, distinct from block/attest/timeout tags
        cert.height,                   // promoted from verifier parameter (see §3.3)
        cert.prevHash,                 // promoted from verifier parameter (see §3.3)
        cert.round,
        cert.prevCertDigest ?? '',     // empty string iff round === 0 (anchor)
        canonicalVoteSet(cert.votes),  // sorted, deduped, signature-excluded (see §3.2)
      ])
    )
  )
```

**Why SHAKE256.** The existing `blockHash` primitive uses `SHA3_SHAKE256`; reusing it avoids a
second hash primitive and keeps the digest width consistent with existing hashes in the protocol.

**Why domain-separate.** The tag `'nerion-viewchange-cert-v1'` is distinct from all other preimage
tags in the codebase (`'polarseek-block-v1'`, `'polarseek-block-sig-v1'`,
`'polarseek-attestation-v1'`, `'polarseek-timeout-v1'`, `'polarseek-vrf-v1'`). This prevents any
cross-context preimage collision between a cert digest and a block hash or attestation message.

### 3.2  Canonical vote set projection

`canonicalVoteSet(votes)` projects and sorts the vote list before it enters the preimage:

```
canonicalVoteSet(votes: readonly TimeoutVote[]) : canonical value =
  encodeCanonical(
    votes
      .map(v => [v.validator, v.suite, v.height, v.prevHash, v.round])  // exclude sig bytes
      .sort()           // lexicographic on the serialized tuple, for sort-order independence
      .filter(unique)   // deduplicate (same validator cannot appear twice)
  )
```

**Signature bytes are excluded from the digest preimage.** This ensures `certDigest` is stable
across equivalent certs regardless of signature-byte representation, encoding, or aggregator
reordering. (Whether to additionally bind the signature set — making grinding over aggregation
harder — is an explicit open audit item; see §7.4.)

**Sort and deduplicate before hashing.** The same discipline the existing quorum-threshold verifier
applies (it iterates `cert.votes` and deduplicates via a `Set<string>`) is reflected in the
digest. An aggregator who reorders votes or inserts duplicates cannot produce a different digest
for a semantically identical cert.

### 3.3  Wire type: `ChainedViewChangeCert`

The new proposed wire type, extending the current `ViewChangeCert`:

```typescript
/**
 * A view-change certificate that forms part of a chain anchored at the last
 * finalized checkpoint. Each cert covers exactly one round.
 *
 * PROPOSED — not implemented. Breaking wire-format change relative to the
 * current ViewChangeCert. Requires a validator-set mode flag to activate.
 */
export interface ChainedViewChangeCert {
  /** The round this cert covers (i.e. validators signed that THIS round timed out). */
  readonly round: number

  /**
   * Block height this cert belongs to.
   * Promoted from a verifier parameter so the cert digest commits to its chain
   * position and cannot be spliced across forks or heights (see §5.3).
   */
  readonly height: number

  /**
   * The hash of the block this cert's chain is anchored to (the parent block).
   * Promoted from a verifier parameter for the same fork-binding reason as height.
   * Every TimeoutVote in votes must carry the same prevHash value.
   */
  readonly prevHash: string  // hex

  /**
   * Digest of the immediately preceding round's ChainedViewChangeCert.
   * ABSENT (or undefined) iff and only iff round === 0, which is the anchor.
   * For round r > 0: prevCertDigest === certDigest(certForRound(r - 1)).
   */
  readonly prevCertDigest?: string  // hex

  /**
   * The quorum of TimeoutVotes justifying this round's timeout.
   * Each vote must carry (height, prevHash, round) matching the cert fields.
   */
  readonly votes: readonly TimeoutVote[]
}
```

**Backward-compatibility note.** Optional fields (`prevCertDigest`, and the promoted `height` /
`prevHash`) allow the struct to be read in the same type position as the current `ViewChangeCert`
in environments where the chain-mode flag is off. When chain-mode is enabled, a verifier that
receives a bare (non-chained) cert treats it as a broken chain and fails closed (see §4.5).

### 3.4  Block type interaction

`Block.viewChangeCert` continues to carry the cert for `round − 1` as a single object. The full
chain `C_0, …, C_{round−2}` must be reachable by the verifier — either carried inline (embedded in
the block as an array of certs) or retrievable from the gossip/storage layer. The choice of
carry-inline vs. gossip-fetch is an **open design question** explicitly deferred to council review
(see §7.1). This ADR specifies the chain structure and verification rule independent of the
transport.

---

## 4  Verification rule: `verifyViewChangeCertChain`

The chained verifier adds a wrapper around the existing `verifyViewChangeCert` per-link primitive.
The per-link primitive remains **unchanged**; its audited threshold/dedup/BigInt/stateless
properties are inherited by each link.

### 4.1  Input

```
verifyViewChangeCertChain(
  set         : ValidatorSet,
  suite       : string,
  height      : number,
  prevHash    : string,
  targetRound : number,         // the round whose timeout the block must justify (= block.round - 1)
  chain       : readonly ChainedViewChangeCert[],
                                // ordered C_0, C_1, …, C_{targetRound}
  finalityNum : number = 2,
  finalityDen : number = 3,
) : boolean
```

### 4.2  Verification steps (all must pass; fail closed on any failure)

**Step 1 — Length and monotonicity.**

- `chain.length === targetRound + 1`.
- For each `k = 0 … targetRound`, `chain[k].round === k` (strictly monotone, no gaps, no
  duplicates).
- `targetRound` must be a non-negative integer (same guard as the current round-negativity check).

**Step 2 — Anchor.**

- `chain[0].prevCertDigest` is `undefined` or the empty string `''`.
- `chain[0].round === 0`.

**Step 3 — Per-link quorum (reuses existing primitive).**

For each `k = 0 … targetRound`:

```
verifyViewChangeCert(set, suite, height, prevHash, k, chain[k], finalityNum, finalityDen) === true
```

This calls the existing, unmodified verifier for each link. Each link must independently be a
valid ≥2/3 cert for exactly `(height, prevHash, k)`. All existing checks — suite binding,
deduplication, BigInt cross-multiply threshold, signature validity per vote — are inherited.

**Step 4 — Position binding.**

For each `k`, `chain[k].height === height` and `chain[k].prevHash === prevHash`. (The existing
per-vote checks inside `verifyViewChangeCert` already enforce this per vote; the cert-level
promotion lets `certDigest` also commit to the fork.)

**Step 5 — Link integrity (the novel check).**

For each `k = 1 … targetRound`:

```
chain[k].prevCertDigest === certDigest(chain[k - 1])
```

`certDigest` is **recomputed locally** from `chain[k - 1]`'s fields; it is never taken from the
wire or trusted from the cert producer. A mismatch in any link rejects the entire chain.

**Step 6 — Fail closed.**

Any of the following causes the entire chain to be rejected (return `false`):

- Wrong chain length.
- Non-monotone or duplicate round numbers.
- Non-anchor cert missing `prevCertDigest`.
- Any link failing `verifyViewChangeCert`.
- Any link with `height ≠ height` or `prevHash ≠ prevHash`.
- Any digest mismatch in Step 5.
- Any missing cert (if certs must be fetched from gossip and one is unavailable, fail closed).
- A `targetRound` that is negative or not a safe integer.

The verifier is **stateless** (no clock), **non-throwing** (structural errors are `false`, not
exceptions), and **monotone-fail-closed** (partial validity confers no privileges).

### 4.3  Callers

`proposeVrf` (`chain.ts:132`) and `verifyFinalized` (`chain.ts:283`) replace the single call to
`verifyViewChangeCert` for `round > 0` with a call to `verifyViewChangeCertChain`, when the
validator set is in chain-mode (see §4.5). All other checks — non-negative round, VRF proof
validity, `vrfLeaderEligible`, `prevHash` extension, suite binding — are unchanged.

### 4.4  Conformance

A new conformance check **C24** (next free id after C23) is added to `conformance/src/suite.ts`
asserting the chain property end-to-end:

- Positive: a complete, digest-linked chain `C_0 … C_{N−1}` admits a round-`N` block.
- Negative-1 (LEDGER-007 exploit): a single high-round cert with no chain is rejected.
- Negative-2: a broken link (`prevCertDigest` mismatch at any position) is rejected.
- Negative-3: a spliced cross-fork/cross-height link is rejected.
- Negative-4: a sub-2/3 intermediate link is rejected.
- Negative-5: a missing intermediate cert (unavailable in gossip) must fail closed.
- Negative-6: a non-chain-mode block presented to a chain-mode set is rejected (downgrade).

`runConformance` total increments 23 → 24; `STATUS.md` and all "23-of-23" references update to
"24-of-24" **in the implementing PR, not in this ADR**.

**No KAT vector regen is required for the frozen corpus.** `conformance/vectors/ps-kat.json` and
`ps-negative.json` carry no ledger/view-change vectors (confirmed by grep); the view-change cert
surface is exercised by vitest in `ledger/test/vrf-chain.test.ts`, not the frozen KAT JSON. So
enabling chaining does **not** invalidate any frozen KAT vector — the HARD CONSTRAINT on KAT
vectors is satisfied.

### 4.5  Mode flag

Gate the new verification behind a per-validator-set boolean `requireCertChain` flag (analogous
to the VRF-mode flag fixed by the validator set in `chain.ts:316`):

- A **chain-mode** validator set (`requireCertChain === true`) rejects any block with `round > 0`
  that does not present a complete chained cert array. A lone single-cert (legacy) block is
  treated as a broken chain and fails closed — the set cannot be downgraded by an individual
  proposer.
- A **legacy-mode** validator set (`requireCertChain === false`) keeps single-cert behaviour
  byte-for-byte identical. All existing tests and the 23-of-23 conformance remain unaffected
  while the flag is off.
- The mode is fixed by the set at validator-set creation time; it cannot be toggled per block.

**No default behaviour changes until council/audit sign-off promotes the flag.** Until then
`ledger/` is byte-for-byte identical to the current tree.

---

## 5  Formal security argument (UNAUDITED sketch — not a proof)

*This section is an internal, ROM-classical security sketch intended as input to the external
consensus/crypto audit. It is NOT a proof, NOT a QROM result, and NOT an audited claim.
Every residual assumption is flagged explicitly.*

### 5.1  Skip cost becomes linear

**Claim.** Under chain-mode, a coalition advancing `N` rounds must produce `N` independently
quorum-signed certs.

**Argument.** The verifier requires `chain[k].prevCertDigest === certDigest(chain[k-1])` for every
`k`, where `certDigest` is recomputed locally and never trusted from the wire. For a chain of
length `N` to be accepted:

1. `chain[0]` must be a valid ≥2/3 cert for round 0 at `(height, prevHash)`. Since sub-1/3
   Byzantine stake cannot forge any valid `TimeoutVote` signature (ML-DSA-87 unforgeability), and
   ≥2/3 honest stake would only sign a vote if round 0 genuinely timed out, `chain[0]` requires a
   genuine ≥2/3 signing ceremony.

2. `chain[1].prevCertDigest` must equal `certDigest(chain[0])`. Because `certDigest` is a
   collision-resistant hash (SHAKE256 over a canonical preimage), a coalition cannot produce a
   `chain[1]` that links to any cert other than the actual `chain[0]` they produced. Since
   `chain[1]` must itself be a valid ≥2/3 cert for round 1, it requires a second independent
   signing ceremony.

3. By induction over `k = 0 … N − 1`: each `chain[k]` requires an independent ≥2/3 signing
   ceremony, and the chain integrity constraint (`prevCertDigest`) prevents any link from being
   fabricated or reused across rounds.

Therefore advancing `N` rounds costs **O(N)** signing ceremonies — one per intermediate round.
Under the current (non-chained) protocol the cost is O(1). The linear cost directly raises the
price of re-rolling the VRF leader: to probabilistically guarantee a given validator appears as
VRF-eligible within `N` rounds, a coalition must actually wait out (or fabricate evidence for)
`N` genuine timeouts.

**Residual assumptions for this argument.**

- (R1) **ML-DSA-87 unforgeability.** Sub-1/3 Byzantine stake cannot produce valid `TimeoutVote`
  signatures for validators it does not control. This is the same assumption underlying the
  existing single-cert verifier and the attestation quorum; it is inherited, not new.
- (R2) **SHAKE256 collision resistance.** A coalition cannot find two distinct certs `C ≠ C'`
  with `certDigest(C) = certDigest(C')`. This is the standard pre-image/collision assumption for
  SHAKE256 in ROM; classical, QROM not analyzed.
- (R3) **`canonicalVoteSet` is genuinely canonical.** No two semantically distinct vote sets
  (counting distinct, quorum-valid voters) produce the same canonical encoding. This requires the
  same dCBOR scrutiny already applied to `blockHash` and `attestMessage`; it is an explicit audit
  item.

### 5.2  No new safety surface

The chain governs only which round may propose. Block finality still requires an independent ≥2/3
attestation quorum over the block hash. Accountable safety and equivocation slashing
(`equivocation.ts`) are untouched. A valid chain does not allow any sub-2/3 set to finalize a
block. The existing attestation equivocation-comparability invariant (round deliberately omitted
from `attestMessage`, LEDGER-EQUIV-001) is preserved — this ADR changes only the *view-change
cert*, not the attestation message.

### 5.3  Fork and replay binding

`certDigest` commits to `(height, prevHash, round, prevCertDigest, canonicalVoteSet)`. The
promoted `height` and `prevHash` fields pin every cert to the same fork of the chain. An adversary
cannot splice a cert produced on a competing fork (different `prevHash`) into a chain on the
canonical fork, because the digest of the spliced cert would embed the wrong `prevHash`, causing a
digest mismatch at the child cert's `prevCertDigest` check. The existing per-vote `(height,
prevHash, round)` binding inside `verifyViewChangeCert` additionally ensures that individual votes
within a spliced cert are also rejected.

### 5.4  Under a ≥2/3 honest-stake quorum

The argument's conclusion is that, under a ≥2/3 honest-stake assumption, a Byzantine leader
cannot forge the chain without an honest quorum co-signing each intermediate round. More
precisely:

> If fewer than 1/3 of stake (by weight) is Byzantine, then for any valid
> `ChainedViewChangeCert` chain `C_0, …, C_{N−1}` accepted by `verifyViewChangeCertChain`,
> each `C_k` was co-signed by a set of validators whose aggregate stake is ≥2/3 of total, and
> whose honest members would only have signed if round `k` genuinely timed out.

This follows from (R1): forging a single cert requires forging ML-DSA-87 signatures for ≥2/3
stake, which the sub-1/3 Byzantine component cannot do unilaterally. The full quorum must include
≥2/3 − (Byzantine fraction) > 0 honest validators who participated willingly.

*The argument above is UNAUDITED. It is stated as a claim to be verified by the external audit,
not as a proven theorem.*

---

## 6  Migration path from current `ViewChangeCert`

### 6.1  Overview

The transition has three phases:

| Phase | Description | Wire change |
|-------|-------------|-------------|
| **A — Design only (this ADR)** | ADR approved; no code written | None |
| **B — Implementation, flag-off** | New types + verifier added; chain-mode flag defaults off; all existing tests pass unchanged | Additive only (optional fields) |
| **C — Activation** | Council/audit signs off; chain-mode enabled for new validator sets | Breaking for new sets; legacy sets unaffected |

### 6.2  Phase B: implementation

The implementing PR (separate, gated on council/audit approval of this ADR) adds:

- **`ledger/src/types.ts`** — add `ChainedViewChangeCert` as a new interface (§3.3). `ViewChangeCert`
  remains unchanged for backward compatibility; the existing `Block.viewChangeCert?: ViewChangeCert`
  field is widened to `ViewChangeCert | ChainedViewChangeCert`. Optional fields in
  `ChainedViewChangeCert` (`prevCertDigest`) keep the struct wire-backward-compatible with legacy
  parsers that ignore unknown fields, though a chain-mode verifier will reject bare legacy certs.

- **`ledger/src/leader.ts`** — add:
  - `certDigest(cert: ChainedViewChangeCert): string` implementing §3.1.
  - `canonicalVoteSet(votes: readonly TimeoutVote[]): ...` implementing §3.2.
  - `verifyViewChangeCertChain(...)` implementing §4.1–§4.2.
  - The existing `verifyViewChangeCert` is the per-link primitive; it is called unchanged inside
    the new chained verifier.

- **`ledger/src/chain.ts`** — in `proposeVrf` and `verifyFinalized`, when the validator set has
  `requireCertChain === true`, replace the single `verifyViewChangeCert` call (at `chain.ts:152`
  and `chain.ts:330`) with `verifyViewChangeCertChain`. When `requireCertChain === false` (default
  until activation), the single-cert path is unchanged.

- **`ledger/test/vrf-chain.test.ts`** — extend with positive and negative cases for the chain
  verifier (§4.4). No existing test is modified.

- **`conformance/src/suite.ts`** — add C24 (§4.4). No existing conformance check is modified.

### 6.3  Phase C: activation for new validator sets

When the external audit and council sign off, new validator sets are created with
`requireCertChain: true`. Existing validator sets continue to operate under single-cert mode until
they are rotated. Validators in chain-mode sets must:

1. Accumulate and gossip all intermediate `ChainedViewChangeCert`s as rounds time out.
2. When proposing at round `r > 0`, assemble the full chain `C_0 … C_{r−1}` and include it with
   the block (or make it available via the gossip layer — see §7.1).
3. When verifying a block, reconstruct or fetch the chain and run `verifyViewChangeCertChain`.

### 6.4  KAT migration

No frozen KAT vectors need regeneration. The new C24 conformance check is a new, additive entry.
Existing vectors (`ps-kat.json`, `ps-negative.json`) and checks C1–C23 remain byte-identical.

---

## 7  Residual design questions and open items

These items are **explicitly deferred to council review and external audit** and must be resolved
before Phase C activation.

### 7.1  Cert availability (most critical open question)

A block carries one `viewChangeCert` object (for `round − 1`). A chain of depth `r` requires all
`r` certs to be verifiable. Three candidate approaches:

**Option A — Carry all certs inline in the block.**
`Block.certChain: readonly ChainedViewChangeCert[]` replaces `viewChangeCert`. Every link is
present in the block. Verification is fully local and stateless. Cost: **O(r) bytes per skip**.
For `r` large (e.g. 100 skipped rounds each with 100 validators), the block becomes megabytes.
Limits practical `MAX_SKIP`; opens a block-size DoS vector if `MAX_SKIP` is set too high.

**Option B — Anchor cert digests in block headers; prove inclusion with a short proof.**
Each block header embeds a `certChainRoot` accumulator (e.g. a Merkle root over all cert digests
`certDigest(C_0) … certDigest(C_{r−1})`). A proposer gossips the individual certs separately;
a verifier fetches and verifies them against the root with an O(log r) Merkle proof. Solves the
byte-size problem but adds a header field, Merkle machinery, and an availability assumption on
gossip. This is Alternative 2 in §9.

**Option C — Gossip-fetch without in-block embedding.**
The block carries only `C_{r−1}` (the current structure). A verifier that needs the full chain
requests earlier certs from the gossip layer. If any cert is unavailable, the verifier fails
closed (§4.2, Step 6). This is the weakest availability guarantee: a withholding minority could
make intermediate certs unavailable, stalling verification of any block that skips many rounds.
Strong only if the gossip layer guarantees cert availability across view changes (which current
`gossip.ts` does not specify).

**Council must choose an option and bound `MAX_SKIP`** (the maximum allowed round skip, below
which a single-link chain is still accepted, above which the full chain is required). A reasonable
default is `MAX_SKIP = 1` (no skipping allowed without a full chain), making every round skip
exactly one cert deep.

### 7.2  Signature-set binding in certDigest

`certDigest` currently excludes raw signature bytes from the preimage (§3.2). An alternative is to
also hash the signature bytes, binding the exact quorum (not just the voter identities) to the
chain. This makes grinding over aggregation order harder but ties the digest to a specific
signature set. The audit should rule on whether the current construction (identity-bound only) is
sufficient or whether signature-set binding is needed.

### 7.3  Per-vote prevCertDigest binding

A stronger construction would include `prevCertDigest` in the signed `TimeoutVote` message itself
(i.e. extend `viewChangeMessage` to take `prevCertDigest`). This would make every signer *attest
to the chain*, not merely to a round timeout. The aggregator could then not construct a fraudulent
link without each signing validator co-attesting to the previous cert. This is a larger protocol
change (new vote wire format, new `viewChangeMessage`); deferred as Alternative 1 (§9) and
recommended as the audit's first escalation if cert-level linking is judged insufficient.

### 7.4  Liveness interaction with chaining

Requiring a full chain must not allow a minority that withheld an intermediate cert to stall
view-change recovery indefinitely. The view-change timeout and the gossip availability guarantees
(ADR-0004 §4) must be re-analyzed under chaining. Specifically: if round-`k` validators produce
`C_k` but it is not reliably gossiped, a subsequent proposer cannot build a valid chain for round
`k + 1`. This could freeze progress if the protocol allows cert withholding as a DoS. The liveness
argument must be reconstructed for the chained protocol; flagged for council.

### 7.5  `canonicalVoteSet` dCBOR scrutiny

`canonicalVoteSet` must be verified to produce a genuinely canonical serialization — no two
distinct validator sets that are quorum-equivalent produce the same encoding, and no aggregator can
grind the sort order to find a collision. This requires the same dCBOR review applied to
`encodeCanonical` elsewhere in the codebase and is an explicit audit item.

---

## 8  Implementation plan summary (design-only today)

This ADR writes **no code and changes no existing file**. The change set, when approved, is:

| File | Change |
|------|--------|
| `ledger/src/types.ts` | Add `ChainedViewChangeCert` interface; widen `Block.viewChangeCert` type |
| `ledger/src/leader.ts` | Add `certDigest`, `canonicalVoteSet`, `verifyViewChangeCertChain`; keep `verifyViewChangeCert` as per-link primitive |
| `ledger/src/chain.ts` | In `proposeVrf` and `verifyFinalized`, gate on `requireCertChain`; call chained verifier when flag is on; no change to default path |
| `ledger/test/vrf-chain.test.ts` | Add positive and negative chain-verifier tests (§4.4) |
| `conformance/src/suite.ts` | Add C24 (§4.4); increment `runConformance` total |
| `docs/STATUS.md`, `docs/SECURITY_FINDINGS.md`, `ADR-0004` inline comments | Update LEDGER-007 from "gap / roadmapped" to "closed by ADR-0034 / C24" **in the implementing PR** |

**Track-B gate:** adding C24 is a conformance-count change that **requires council approval before
any KAT or conformance change**. The implementing PR must be reviewed and approved before merging.
No KAT JSON vector is touched (confirmed: no ledger/view-change vectors in `ps-kat.json`).

**Push / merge policy:** per the `always-commit-publish-deploy` standing directive, when the
implementing PR is ready it is committed and pushed to the public `main` branch — not parked
locally. This ADR itself (design-only) may be committed to the worktree and pushed to main as a
documentation commit with no code changes.

---

## 9  Alternatives considered

1. **Per-vote `prevCertDigest` binding (bind chain into the signed TimeoutVote) — DEFERRED,
   stronger.** Including the previous cert's digest in `viewChangeMessage(...)` so each *signer*
   attests to the chain is the most rigorous construction. It removes any trust in the aggregator
   to carry the link faithfully. It is a larger signing-surface change (new vote message format,
   new `viewChangeMessage` preimage, new `TimeoutVote` wire field). The cert-level link specified
   in this ADR is the minimal step that makes skipping O(N); recommend as the audit's first
   escalation if this is judged insufficient.

2. **Logarithmic / Merkle cert-chain accumulator — DEFERRED.** Embed a `certChainRoot` Merkle
   root in block headers; prove a contiguous cert run with an O(log N) inclusion proof. Solves the
   O(N)-bytes inline-carry cost while keeping stateless verification. Adds a new header field,
   Merkle machinery, and a gossip-fetch path. Revisit if the byte cost of Option A (§7.1) is
   unacceptable for realistic skip depths.

3. **Round-rate limiting by wall-clock — REJECTED.** Bounding how fast rounds advance via wall
   time would re-introduce a clock into a deliberately stateless verifier (`leader.ts` consults no
   clock by design; LEDGER-VRF-001 is partly about rejecting clock-gated assumptions) and is not
   stake-accountable. Rejected as the primary fix.

4. **Bind round into `attestMessage` to prevent equivocation-comparability loss — REJECTED
   (adjudicated).** Binding `round` into attestations was considered and decided against: it breaks
   same-height equivocation comparability that accountable safety depends on (LEDGER-EQUIV-001).
   The round-skip gap must be closed in the view-change cert, not the attestation. This ADR does
   exactly that.

5. **Accept LEDGER-007 (do nothing) — REJECTED.** Defensible on the narrow safety-only framing,
   but it is a named, disclosed gap with a known rigorous fix. The apex roadmap (U4) commits to
   closing it; the grant audit tracks it. Leaving it open indefinitely is not acceptable.

---

## 10  Consequences

**Fairness (when activated):** a ≥2/3 coalition can no longer cheaply re-roll the VRF leader.
Advancing `N` rounds requires `N` independent quorum-signed certs — **O(N)** cost. The
leader-allocation bias of LEDGER-007 is mitigated for validator sets that enable chain-mode.

**Safety (unchanged):** no new surface is added to block finality. The ≥2/3 attestation quorum
for each block, accountable safety, and equivocation slashing are untouched.

**Wire format:** `ChainedViewChangeCert` is a new interface with optional fields; `ViewChangeCert`
is unchanged. Legacy validator sets continue using `ViewChangeCert` byte-for-byte.

**Verification performance:** O(r) per-link `verifyViewChangeCert` calls per skip of `r` rounds.
Each call is O(|votes|) ML-DSA-87 verifications. Honest networks rarely skip many rounds (skipping
only happens after genuine timeouts); the common path is one cert per block (cheap). Large skips
are expensive by design.

**Verification stays stateless and fail-closed:** no clock; every failure path returns `false`
rather than throwing; partial chain validity confers no privileges.

**Regression risk while deferred:** zero. Default-off behind `requireCertChain`; all 313 tests
and 23-of-23 conformance checks are unaffected until the implementing PR lands.

**Still UNAUDITED:** this is a design record and a cryptographic argument, not a security proof.
The cert-availability question (§7.1) and `canonicalVoteSet` canonicality (§7.5) are explicitly
unresolved and handed to council and external audit. No implementation proceeds without their sign-off.

**DeepSeek PhD seat council note (Sprint-1 synthesis).** The highest-severity finding from the
Sprint-1 council sweep is in ADR-0033 (the per-bit Fiat–Shamir challenge binding is mathematically
incompatible with Sigma-protocol special-soundness and must be replaced with a single-scalar
Fiat–Shamir challenge over the full transcript — statement + all branch commitments + domain
separator). ADR-0032's generator-pinning invariant is sound subject to the standard NUMS
assumption. The present ADR-0034 round-skip argument is judged internally consistent under the
≥2/3 honest-stake and ML-DSA-87 unforgeability assumptions, with the availability question (§7.1)
as the primary unresolved engineering item.

---

## 11  References

- `ledger/src/types.ts` — `TimeoutVote`, `ViewChangeCert`, `Block`, `BlockHeader` (current types)
- `ledger/src/leader.ts` — `verifyViewChangeCert`, `viewChangeMessage`, `vrfAlpha`
- `ledger/src/chain.ts` — `proposeVrf` (lines 132–182), `verifyFinalized` (lines 283–), LEDGER-007
  inline comment (lines 317–329), `blockHash`, `encodeCanonical`
- `ledger/test/vrf-chain.test.ts` — current view-change cert test surface
- `docs/adr/ADR-0004-vrf-sortition.md` — VRF sortition + view-change; names LEDGER-007 and "a
  cert chain (each cert referencing the prior) is the rigorous fix"
- `docs/adr/ADR-0019-chained-view-change-certs.md` — companion ADR with additional alternatives
  and KAT regen detail (written during Sprint-1; this ADR formalizes the full formal argument)
- `docs/STATUS.md`, `docs/SECURITY_FINDINGS.md` — LEDGER-007 disclosure (fairness-only, ≥2/3-gated)
- `docs/APEX_SPRINT_BACKLOG.md` (B3), `docs/APEX_UPGRADE_PROGRAM.md` (U4) — this work item
- `conformance/src/suite.ts` (C22/C23 pattern; C24 to be added on implementation)
- `conformance/vectors/ps-kat.json` — no ledger vectors (confirmed; no regen required)
- RFC 9381 (ECVRF) — the VRF scheme whose leader-draw fairness this ADR hardens
- SHAKE256 / SHA3 — NIST FIPS 202 (the digest primitive used in `certDigest`)
