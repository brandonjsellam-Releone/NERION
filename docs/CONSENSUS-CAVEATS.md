<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nerion — Consensus Protocol Caveats for Auditors

> **Intended audience:** external security auditors, cryptography reviewers, and conformance
> assessors examining the pure-PoS ledger in `ledger/`.
>
> **What this document is:** a plain enumeration of honest, not-yet-closed limitations of the
> consensus layer. Every item here is a **known-open item stated proactively**; none is claimed
> resolved. Nerion follows a transparent-disclosure policy: auditors should see these stated
> plainly rather than having to rediscover them.
>
> **What this document is not:** a complete threat model (see `THREAT_MODEL.md`), a
> conformance report (see `conformance/`), or a legal or security opinion. Nothing here
> constitutes a claim of auditedness, FIPS validation, or patent non-infringement.

---

## Caveat 1 — Round-Skip Attack Surface (LEDGER-007)

### What the code does

A round-`r` block carries a ≥2/3-stake **view-change certificate** (VCC) that proves round `r-1`
timed out, and nothing more. Concretely:

- `verifyFinalized` and `proposeVrf` in `ledger/src/chain.ts` call `verifyViewChangeCert`
  with `block.header.round - 1`.
- The cert message constructed in `ledger/src/leader.ts` binds only
  `(suite, height, prevHash, round)`.

Because the cert attests only that the immediately prior round timed out, **no cert chains
back through every skipped round to round 0**.

### The risk

A ≥2/3-stake coalition can publish a single VCC for some round `r-1` and jump straight to an
arbitrary round `r`, re-drawing the VRF leader sortition among themselves at will. This is a
**fairness weakening**: the coalition already controls liveness (it holds ≥2/3 stake), so the
cost of a round-skip is zero beyond that prerequisite.

**Safety is unaffected**: every block still requires its own independent 2/3-stake attestations
to finalize, regardless of which round it carries. The skip cannot cause a safety violation
in the BFT sense.

### Severity

**MEDIUM** — exploitable only by an adversary that already controls ≥2/3 stake and has the
motivation to suppress a specific VRF leader. The primary consequence is leader-selection
manipulation (denial-of-leadership against an honest validator), not ledger corruption.

### Mitigation design (deferred)

**ADR-0018 (cert-chain):** each VCC would reference the previous VCC, forming a chain from
the last finalized block through every skipped round. This makes round-skipping auditable and
costly (requires producing one cert per skipped round, each signed by ≥2/3 stake).

**Status: not implemented.** ADR-0018 is a forward design item.

### Current operator mitigation

Monitor gossip logs for abnormally large gaps between `block.header.round` values at the same
`height`. A sustained large gap without a corresponding liveness event warrants investigation.

---

## Caveat 2 — Validator-Set / Epoch Binding Absent from Consensus Messages

### What the code does

The signed messages that form the consensus protocol bind `(suite, height, prevHash, round)`
but **no validator-set identifier and no epoch number**. Specifically:

- `attestMessage` in `ledger/src/chain.ts`
- `viewChangeMessage` in `ledger/src/leader.ts`
- `EquivocationProof` and `TimeoutVote` in `ledger/src/equivocation.ts` and
  `ledger/src/types.ts`

All four structures omit any set/epoch tag. Verification is always performed against a
caller-supplied `ValidatorSet`; in the current single-set test harness this latency is not
observable.

### The risk

A vote or attestation produced under one validator-set configuration could be **replayed
against a different set** that happens to share the same `(height, prevHash, round, suite)`.
This is the **epoch-substitution attack**: consent given under epoch N is transferred to epoch
M by a replayer who controls or observes both epochs, without the signers having signed over
epoch M's membership or stake distribution.

The risk is **latent** in the current single-set deployment and becomes a **live risk under any
epoch transition or membership/stake reconfiguration**.

### Severity

**MEDIUM-HIGH** under reconfiguration conditions; **LOW** in a static single-epoch deployment.

### Mitigation design (deferred)

**Track-B item B5 (validator-set-id binding):** bind an explicit set/epoch identifier (e.g.,
a hash of the `ValidatorSet` structure) into every consensus signature preimage. This makes
cross-epoch replay detectable at verification time.

**Status: not implemented.**

### Current operator mitigation

Epoch numbers are included in the broader message context and validator sets rotate on a
schedule that does not re-use `(height, prevHash, round)` tuples across epochs in a live
deployment. Operators must not reuse block-hash prefixes or heights across distinct validator
sets.

---

## Caveat 3 — Equivocation Detected but Slashing Not Wired End-to-End (LEDGER-006)

### What the code does

`ledger/src/equivocation.ts` provides three helpers:

1. `detectEquivocations` — builds a slashable proof when a validator double-signs two distinct
   blocks at the same height.
2. `verifyEquivocationProof` — verifies such a proof.
3. `slash` — returns a new `ValidatorSet` with the offender's stake forfeit.

These helpers are **sound as pure functions** and are exercised by tests.

### What the code does NOT do

The live ledger path — `Ledger.submit`, `appraise`, and `verifyFinalized` in
`ledger/src/chain.ts` — **never calls any of the above**. It does not:

- gather conflicting attestations across blocks,
- build equivocation proofs,
- apply a `slash`, or
- persist any slashing state across blocks.

`chain.ts` itself documents this: `"Equivocation slashing is deferred (LEDGER-006)"`.

A related guard (LEDGER-EQUIV-001) ensures the detector cannot be abused to slash an honest
validator for legitimate cross-height attestations — that guard is implemented.

### The risk

Accountable safety (the property that a safety violation is economically punished) is
**not operational**. The evidence primitive exists; the enforcement pipeline does not. A
Byzantine validator can equivocate, and the equivocation will be detectable offline from log
data, but no automatic stake forfeiture will occur.

### Severity

**HIGH** for any deployment relying on economic accountability to deter Byzantine behavior.
**LOW** for a research/pre-pilot deployment where honest-validator assumptions hold and
slashing is not a stated security guarantee.

### Mitigation design (deferred)

**Track-B item B8 (epoch-bound slash):** wire `detectEquivocations` into the block-appraisal
path, add an equivocation-report ingress, and bound slash validity to finalized epochs within
the unbonding window (to prevent stale-proof submissions against already-unbonded validators).

**Status: not implemented.**

### Current operator mitigation

Operators should monitor for double-signed block headers in gossip and manually review any
equivocation evidence. Do not represent the system as providing automatic slashing to external
parties.

---

## Caveat 4 — Cross-Plane Key Isolation Not Formally Verified (Open Audit Item)

### What the code does

Key material is **designed to be per-plane**: Plane 1 uses HMAC-SHA-384 PermitToken keys,
Plane 2 uses ML-DSA-87 receipt signing keys, and Plane 3 uses PoS ledger and governance keys.
Separate key paths and signing surfaces are implemented.

### The open item

Per `THREAT_MODEL.md` §3:

> "Key isolation is **designed into the implementation** (each plane uses distinct key material
> and separate signing paths), but the end-to-end cross-plane isolation guarantee has **not been
> formally verified or externally audited**. Treat this as an open audit item, not a closed
> guarantee."

The end-to-end property — that a compromise contained in one plane cannot silently grant
authority in another — depends on key separation and cross-plane verification. Whether this
holds unconditionally has not been proven by a formal method or confirmed by an independent
cryptography auditor.

### Severity

**OPEN** — design intent is present and implemented; formal proof and external audit are absent.
Auditors should treat cross-plane key isolation as an **asserted property pending verification**,
not a closed guarantee.

### Mitigation design

External crypto/consensus audit reviewing cross-plane key paths and signing surfaces. No code
change is required unless the audit reveals a gap; this is a verification gap, not a known
implementation defect.

---

## Caveat 5 — ZK Policy-Satisfaction Proof Soundness is Classical (Transitional Only)

### What the code does

`disclosure/policyproof.ts` implements a conservative ZK Policy-Satisfaction Proof subset
(ADR-0006, C21): hidden-amount `amount ≤ ceiling` and `aggregate + amount ≤ cap` over a
range proof. The commitment scheme (`disclosure/commitbind.ts`, ADR-0013) uses structural
binding to prevent substitution attacks.

### The limitation

Per `STATUS.md`:

> "Proof soundness is classical/transitional, discrete-log."
> "The proof's zero-knowledge is also only ROM-proven, not QROM-analyzed."

The commitment hiding is information-theoretic (PQ); the proof soundness is classical (relies
on the discrete-log assumption). A cryptographically-relevant quantum computer (CRQC) that
can solve discrete log would break the soundness of the ZK proof, not merely the hiding.

The v:2 receipt schema, node wiring, and external ZK audit are pending.

### Severity

**MEDIUM** in the long-range PQ threat model. The current construction is described as
"transitional" consistently across project documentation. Auditors must not represent the
ZK layer as post-quantum end-to-end.

### Mitigation design

Migration to a lattice- or hash-based commitment scheme (see `STATUS.md`, "Top forward
upgrade") would make ZK soundness post-quantum. The v:2 receipt wiring and an external ZK
audit are prerequisites for any production ZK claim.

**Status: forward work item; not implemented.**

---

## Summary Table for Auditors

| # | Identifier | Area | Severity | Status |
|---|---|---|---|---|
| 1 | LEDGER-007 | Round-skip fairness gap | MEDIUM | Open; ADR-0018 deferred |
| 2 | B5 | Validator-set / epoch binding absent | MEDIUM-HIGH (under reconfig) | Open; Track-B deferred |
| 3 | LEDGER-006 | Slashing not wired end-to-end | HIGH (economic accountability) | Open; B8 deferred |
| 4 | THREAT-§3 | Cross-plane key isolation unverified | OPEN (design vs. proof) | Pending external audit |
| 5 | ADR-0006 | ZK soundness classical/transitional | MEDIUM (long-range PQ) | Forward work item |

All items are **known-open**. None is unknown. None is claimed resolved.

---

## Disclosure Policy Note

Nerion follows **transparent disclosure**: auditors receive the list of known-open items
proactively, so that an audit is spent verifying claims rather than rediscovering documented
gaps. This document will be updated as items are closed or new ones are identified.

Conformant ≠ validated; built ≠ audited; design-around ≠ legal opinion.
See `FTO_TODO.md` for patent-counsel and export-control gates.
See `AUDIT_PACKAGE.md` for the full auditor-readiness package.
See `LAUNCH_READINESS.md` for the four external gates that must close before any production claim.
