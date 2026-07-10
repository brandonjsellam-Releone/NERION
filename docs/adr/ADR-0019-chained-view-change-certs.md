<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0019: Chained view-change certificates (close the LEDGER-007 round-skip fairness gap)

**Status: Proposed — DESIGN ONLY, UNIMPLEMENTED.** This ADR specifies a consensus-rule change to the
view-change certificate. It is a _design decision record_, not a security result, and **routes to
external audit / council review** before any code, KAT, or behaviour change. No part of the ledger is
modified by this ADR. The construction is **UNAUDITED**; the soundness argument below is an internal
sketch with its residual assumptions flagged, **never** a proven or audited claim. Date: 2026-06-21.
Addresses the documented **LEDGER-007** caveat
([ADR-0004](./ADR-0004-vrf-sortition.md), `ledger/src/chain.ts`, `docs/STATUS.md`,
`docs/SECURITY_FINDINGS.md`); backlog item **B3 / U4**
([APEX_SPRINT_BACKLOG.md](../APEX_SPRINT_BACKLOG.md),
[APEX_UPGRADE_PROGRAM.md](../APEX_UPGRADE_PROGRAM.md)).

## Context

The P4 ledger uses VRF-private leader sortition with a view-change liveness fallback (ADR-0004). When a
round times out, ≥2/3 of stake sign `TimeoutVote`s and the votes are bundled into a `ViewChangeCert`
that justifies advancing the round. The current cert and its verifier are in `ledger/src/`:

```ts
// ledger/src/types.ts
export interface TimeoutVote {
  readonly height: number
  readonly prevHash: string
  readonly round: number
  readonly validator: string
  readonly suite: string
  readonly sig: Bytes
}
export interface ViewChangeCert {
  readonly round: number
  readonly votes: readonly TimeoutVote[]
}
```

A round-`r` block (for `r > 0`) carries a `ViewChangeCert` for round `r - 1`, verified by
`verifyViewChangeCert(set, suite, height, prevHash, r - 1, cert, …)` (`ledger/src/leader.ts:80`) and
re-checked by the light-client path `verifyFinalized` (`ledger/src/chain.ts:323`). The verifier is
stateless and sound _for what it proves_: sub-1/3 stake cannot forge a cert; it is bound to
`(height, prevHash, round)` so it cannot be replayed across forks or heights; and the quorum threshold
is an exact BigInt cross-multiply (LEDGER-PRECISION-002).

### The gap (LEDGER-007)

A round-`r` block proves **only that round `r - 1` timed out** — _one_ cert — not that rounds
`0, 1, …, r - 1` each timed out in sequence. Consequently a **≥2/3 coalition** can mint a single
`ViewChangeCert` for an arbitrarily large round `r - 1` and immediately propose at round `r`, **skipping
intervening rounds at no cost**. Because the VRF leader is re-drawn per round
(`vrfAlpha(prevHash, round)`, `ledger/src/leader.ts:26`), skipping rounds lets the coalition cheaply
**re-roll the leader draw among themselves** until a round whose VRF leader is one of their own — a
**fairness/leader-allocation weakening**.

The honest scope, already recorded in the code and findings, is:

- **Safety is unaffected.** Each block still needs its own ≥2/3 attestations and accountable-safety /
  equivocation slashing is independent of which round won (`docs/SECURITY_FINDINGS.md`,
  `equivocation.ts`). Round is _deliberately_ omitted from `attestMessage` so all same-height
  attestations stay equivocation-comparable (LEDGER-EQUIV-001) — this ADR does not touch that.
- **Exploitable only by a quorum that already controls liveness.** A <1/3 adversary cannot forge any
  cert, chained or not, so it cannot skip at all. The gap strictly concerns _fairness of leader
  allocation among an already-colluding ≥2/3_.

The cost of skipping `N` rounds today is **O(1)** (one cert for the target round). The intended
property is that skipping `N` rounds should cost **O(N)** — a _chain_ of `N` valid certs — so that
re-rolling the leader is linearly expensive rather than free. ADR-0004 already names "a cert chain
(each cert referencing the prior) is the rigorous fix"; this ADR specifies that chain.

## Decision

Make each `ViewChangeCert` **reference the digest of the previous round's cert**, so a block at round
`r` must present (transitively) a verifiable chain of `r` certs anchored at round 0. Advancing `N`
rounds then requires `N` independently-quorum-signed certs (skip cost **linear in rounds**), not one.

### 1. Cert digest

Define a canonical, domain-separated digest over a cert's _quorum-relevant_ content. Using the
project's existing `encodeCanonical` + `SHA3_SHAKE256` (as `blockHash` does in `chain.ts`):

```
certDigest(cert) =
  SHAKE256( encodeCanonical([
    'nerion-viewchange-cert-v1',         // distinct domain tag
    cert.height,                          // see §3: height/prevHash promoted onto the cert
    cert.prevHash,
    cert.round,
    cert.prevCertDigest ?? '',            // '' only for the round-0 anchor
    canonicalVoteSet(cert.votes),         // sorted, deduped, signature-independent (see §4)
  ]) )
```

`canonicalVoteSet` sorts votes by `validator` and projects each to its quorum-relevant tuple
`(validator, suite, height, prevHash, round)` — **excluding the raw signature bytes** so the digest is
stable across equivalent certs and cannot be ground by a malicious aggregator who reorders or
re-pads votes. (Whether to additionally bind the signature set is an open audit question — see
_Residual assumptions_.)

### 2. Cert struct change (`ViewChangeCert`)

```ts
export interface ViewChangeCert {
  readonly round: number
  readonly votes: readonly TimeoutVote[]
  /** hex certDigest of the round-(round-1) cert. ABSENT iff round === 0 (the anchor). */
  readonly prevCertDigest?: string
}
```

- Round 0 is the **anchor**: `prevCertDigest` is absent (or the empty string in the preimage).
- Round `r > 0`'s cert MUST carry `prevCertDigest === certDigest(certForRound(r - 1))`.
- The `TimeoutVote` struct is **unchanged** (no per-vote chaining field): the chain link lives on the
  cert, and the votes' existing `(height, prevHash, round)` binding already prevents cross-fork /
  cross-height replay. (An alternative that binds the prev digest into each _vote's_ signed message is
  considered and deferred in _Alternatives_ — it is stronger but a larger protocol change.)

`Block.viewChangeCert` continues to carry the cert for `round - 1`; the _chain_ it heads is validated
by following `prevCertDigest` links. Because a block only carries one cert object, a full chain must be
reconstructable by the verifier — see §5 (cert availability) for the honest open question this raises.

### 3. Height / prevHash on the cert

Promote `height` and `prevHash` onto `ViewChangeCert` (today they are verifier _parameters_, derived
per-vote). This is required so a cert's digest commits to its chain position and so a child cert's
`prevCertDigest` pins the parent to the **same `(height, prevHash)` fork** — preventing a coalition
from splicing a cert computed on one fork into a chain on another. The values must equal every
contained vote's `height` / `prevHash` (already checked per vote in `verifyViewChangeCert`).

### 4. Verification rule (`verifyViewChangeCertChain`)

Add a chained verifier; keep the existing single-cert `verifyViewChangeCert` as the **per-link**
primitive (each link must independently be a valid ≥2/3 cert for its own round). A chain for target
round `r - 1` at `(height, prevHash)` is valid iff:

1. **Per-link quorum.** For each round `k = 0 … r - 1`, the cert `C_k` passes the existing
   `verifyViewChangeCert(set, suite, height, prevHash, k, C_k, finalityNum, finalityDen)` — i.e. ≥2/3
   distinct, suite-matched, deduped, signature-valid `TimeoutVote`s for exactly `(height, prevHash, k)`.
   This reuses the audited threshold/dedup/BigInt logic unchanged.
2. **Anchor.** `C_0.prevCertDigest` is absent/empty.
3. **Link integrity.** For each `k = 1 … r - 1`, `C_k.prevCertDigest === certDigest(C_{k-1})`,
   recomputed locally (never trusted from the wire).
4. **Position binding.** Every `C_k.height === height` and `C_k.prevHash === prevHash`.
5. **Fail-closed.** Any missing link, digest mismatch, non-monotone/duplicate round, sub-2/3 link, or
   suite mismatch ⟹ the chain is invalid; the block's round is rejected exactly as a missing cert is
   today (`'round > 0 without a valid 2/3 view-change certificate'`). Like the current verifier it is
   **stateless** (consults no clock) and never throws out (a bogus suite is a failed verification, not
   an exception).

`proposeVrf` (`chain.ts:125`) and `verifyFinalized` (`chain.ts:276`) call the chained verifier instead
of the single-cert check for `round > 0`. The leader-eligibility, VRF-proof, suite-binding,
prevHash-extends, and round-non-negative checks are all unchanged.

### 5. Flags / rollout

- Gate behind a per-validator-set **`requireCertChain`** mode flag (analogous to how VRF-mode is fixed
  by the validator set, not per block, in `chain.ts:309`). A chain-mode set rejects a lone non-chained
  cert as a downgrade; a legacy set keeps single-cert behaviour. **The mode is fixed by the set so a
  coalition cannot per-block opt down to the cheaper single-cert path.**
- No default behaviour changes until council/audit sign-off promotes the flag; until then `ledger/`
  behaviour is byte-for-byte identical and all existing tests/KATs pass unchanged.

## Soundness / security argument (UNAUDITED sketch — not a proof)

_Informal, internal, pre-audit. Stated as an argument to be checked, not a guarantee._

- **Skip cost becomes linear.** To legitimately reach round `r`, a coalition must produce `C_0 … C_{r-1}`
  where each `C_k` is an independent ≥2/3 cert for its own round and each link digest matches. Since
  sub-1/3 cannot forge any single cert (unchanged property), and the digest chain is recomputed locally,
  a coalition cannot manufacture intermediate links it did not actually sign. Advancing `N` rounds thus
  requires `N` quorum-signed certs — **O(N)** signing work — instead of one. This raises the cost of
  re-rolling the VRF leader from free to linear, which is the intended fairness hardening.
- **No new safety surface.** The chain governs _only which round may propose_; finality is still ≥2/3
  attestations on the block and accountable safety / equivocation slashing are untouched. A valid chain
  does not let any sub-2/3 set finalize anything.
- **Fork / replay binding.** `certDigest` commits to `(height, prevHash, round, prevCertDigest,
voteSet)`, and §3 pins every link to the same fork, so a cert from another fork/height/round cannot
  be spliced into a chain (extends the existing per-cert `(height, prevHash, round)` binding to the
  chain).

### Residual assumptions (honest — must hold for the argument to stand)

- **Cert availability.** A block carries one cert object, but the verifier needs the _whole_ chain.
  Either the block must transitively carry/reference all `r` certs, or the protocol must guarantee a
  verifier can fetch every prior cert. If a verifier cannot obtain an intermediate cert it must
  **fail closed** (treat the chain as invalid), or the linearity property is only enforced at the
  proposer, not the light client. **This is the single biggest open design question and must be
  resolved in review** (carry-in-block vs. gossip-fetch vs. anchoring digests in the prior block).
  Naively chaining `r` full certs is **O(r) bytes per skip** — a DoS/availability tradeoff the council
  must weigh (see _Alternatives_ for a logarithmic variant).
- **Honest threshold.** The whole mechanism only constrains a ≥2/3 coalition's _fairness_; it assumes
  the existing ≥2/3-honest-stake safety assumption. It does **not** defend against ≥2/3 that is willing
  to pay the linear cost — it makes skipping _expensive_, not _impossible_.
- **Digest robustness.** Soundness assumes `canonicalVoteSet` is genuinely canonical (no two distinct
  quorums share a digest, no aggregator can grind reorderings). This needs the same dCBOR/canonical
  scrutiny the rest of the codebase applies and is an explicit audit item.
- **Liveness interaction.** Requiring a full chain must not let a withholding minority stall recovery
  (e.g. by making an intermediate cert unavailable). The view-change timeout / fallback interaction
  (ADR-0004 §4) must be re-checked under chaining — flagged for council.
- **Classical / UNAUDITED.** As with all of `ledger/`, this is internal-review level. No formal model;
  no proof; external ROS / ToB audit still applies.

## Implementation plan (DEFERRED to council review — specified, not built)

This ADR changes **nothing** in the tree. When/if approved, the change set is:

- **`ledger/src/types.ts`** — add optional `prevCertDigest?: string` and promote `height` / `prevHash`
  onto `ViewChangeCert` (§2–§3). Optional fields keep the struct backward-compatible.
- **`ledger/src/leader.ts`** — add `certDigest(cert)` and `verifyViewChangeCertChain(...)` (§1, §4);
  keep `verifyViewChangeCert` as the per-link primitive (unchanged).
- **`ledger/src/chain.ts`** — in `proposeVrf` and `verifyFinalized`, replace the single-cert check at
  `round > 0` with the chained verifier; add the `requireCertChain` set-mode gate (§5).
- **Behind flags:** the new behaviour is inert until the validator-set `requireCertChain` mode is on.
  Default-off ⟹ no behaviour change ⟹ existing suites green with no regen.

### KAT / conformance regen plan

- **No JSON KAT regen needed for the corpus.** `conformance/vectors/ps-kat.json` and `ps-negative.json`
  cover the crypto-suite / oracle / disclosure surface; **grep confirms they carry no
  ledger/view-change vectors today** — the view-change cert is exercised by **vitest** in
  `ledger/test/vrf-chain.test.ts` (e.g. the `round > 0 needs a 2/3 view-change cert` case), not the KAT
  JSON. So enabling chaining does **not** invalidate any frozen KAT vector.
- **Ledger tests (when implemented):** extend `ledger/test/vrf-chain.test.ts` with positive cases
  (a full `C_0 … C_{r-1}` chain admits a round-`r` block) and negative cases that must all reject:
  (a) a single high-round cert with no chain (the LEDGER-007 exploit — must now fail), (b) a broken link
  (`prevCertDigest` mismatch), (c) a spliced cross-fork/cross-height link, (d) a sub-2/3 intermediate
  link, (e) a missing/unavailable intermediate cert (fail-closed), (f) a non-chain-mode block rejected
  by a `requireCertChain` set (downgrade).
- **Conformance suite:** add a new check — **id reserved as C25** (2026-07-08: ADR-0020's own deferred
  check landed first as **C24** — "a validator-set attestation bundle does NOT finalize under a
  different reconfiguration epoch" — so this ADR's check must take the next free id, C25, when
  implemented, to avoid a collision) in `conformance/src/suite.ts` asserting the chained property
  end-to-end — "advancing N rounds requires N valid chained certs; a lone high-round cert is rejected;
  a broken link is rejected" — mirroring the C22/C23 style (self-contained, boolean). `runConformance`
  total would increment **24 → 25**; the `STATUS.md` conformance count and the "24-of-24" references
  are bumped to 25-of-25 **in the implementing PR, not here**.
- **Docs to update in the implementing PR:** flip the LEDGER-007 caveat in `ADR-0004`, `STATUS.md`,
  `SECURITY_FINDINGS.md`, and the inline comments at `chain.ts:317-322` from "documented gap / rigorous
  fix roadmapped" to "closed by ADR-0019 / C24". **None of those edits are made by this ADR.**

## Alternatives considered

1. **Bind `prevCertDigest` into each `TimeoutVote`'s signed message (per-vote chaining) — DEFERRED,
   stronger.** Including the prior cert digest in `viewChangeMessage(...)` would make every signer
   _attest to the chain_, not just to a round timeout, removing any reliance on a faithful aggregator to
   carry the link. It is the more rigorous construction but a larger, signing-surface change; the
   cert-level link in this ADR is the minimal step that already makes skipping O(N). Recommended as the
   audit's first escalation if cert-level linking is judged insufficient.
2. **Logarithmic / accumulator skip proof (Merkle or hash-chain over certs) — DEFERRED.** Anchor each
   round's cert digest into the next block header and prove a contiguous run with an O(log N) inclusion
   proof instead of carrying N full certs. Solves the O(N)-bytes availability cost but adds an
   accumulator + header field and more proof machinery; revisit if the byte cost of the straightforward
   chain is unacceptable.
3. **Round-rate limiting / timeout-Δ enforcement — REJECTED as the fix.** Bounding how fast rounds may
   advance via wall-clock would re-introduce a clock into a deliberately **stateless** verifier
   (`leader.ts` consults no clock by design) and is not stake-accountable. Orthogonal at best.
4. **Bind `round` into `attestMessage` so attestations themselves pin the round — REJECTED (already
   adjudicated).** This was considered and decided **against** in the consensus audit
   (`SECURITY_FINDINGS.md`): binding `round` would break the same-height equivocation-comparability that
   accountable safety relies on (LEDGER-EQUIV-001). The round-skip gap must be closed in the _view-change
   cert_, not the attestation — which is exactly what this ADR does.
5. **Do nothing (accept LEDGER-007) — REJECTED.** Defensible on the narrow ground that it is
   fairness-only and ≥2/3-gated, but it is a disclosed, named gap with a known rigorous fix; the apex
   roadmap (U4) commits to closing it.

## Consequences

- **Fairness:** a ≥2/3 coalition can no longer cheaply skip to re-roll the VRF leader; doing so costs a
  full quorum-signed cert _per round skipped_. The leader-allocation bias of LEDGER-007 is mitigated
  (when the mode is enabled and the cert-availability residual is resolved).
- **Schema:** `ViewChangeCert` gains optional `prevCertDigest` + on-cert `height`/`prevHash`. Optional
  fields keep wire/struct backward compatibility; legacy (single-cert) sets keep working.
- **Cost:** carrying a full chain is O(N) bytes per N-round skip (Alternative 2 is the escape hatch if
  that is too heavy). Honest skips are rare (skipping only happens after real timeouts), so the common
  path is cheap.
- **Verification stays stateless and fail-closed.** No clock is introduced; every failure mode rejects
  exactly as a missing cert does today.
- **No regression risk while deferred:** default-off behind `requireCertChain`; the tree is unchanged by
  this ADR, so the full gate and conformance (currently 760 tests / 24-of-24, per STATUS.md) remain
  green until the implementing PR lands.
- **Still UNAUDITED:** this records a design decision and a fix _plan_, not a security result. The
  cert-availability question (Residual assumptions) and the digest-canonicalisation question are
  unresolved and explicitly handed to council / external audit.

## References

- `docs/adr/ADR-0004-vrf-sortition.md` — VRF sortition + view-change; names LEDGER-007 and "a cert chain
  … is the rigorous fix".
- `ledger/src/leader.ts` (`verifyViewChangeCert`, `viewChangeMessage`, `vrfAlpha`),
  `ledger/src/chain.ts` (`proposeVrf`, `verifyFinalized`, LEDGER-007 inline comment lines 317–322),
  `ledger/src/types.ts` (`TimeoutVote`, `ViewChangeCert`).
- `ledger/test/vrf-chain.test.ts` — current view-change cert test surface.
- `docs/STATUS.md`, `docs/SECURITY_FINDINGS.md` — LEDGER-007 disclosure (fairness-only, ≥2/3-gated).
- `docs/APEX_SPRINT_BACKLOG.md` (B3), `docs/APEX_UPGRADE_PROGRAM.md` (U4) — this work item.
- `conformance/src/suite.ts` (C22/C23 pattern; new C24 to be added on implementation),
  `conformance/vectors/ps-kat.json` (no ledger vectors — confirmed).
