<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Team Apex — Round-4 audit (2026-06-21): deepest surfaces

**Scope:** the Rust hot-path, conformance/KAT integrity, concurrency/TOCTOU, the standalone external
verifiers, capability-revocation enforcement, and a final formal ZK-soundness re-derivation. 6 surfaces,
CHUNK=2, dual-refuter. As established in Round 2b, the finder *summaries* were re-checked by hand for concrete
candidates the automated gate dropped — and this round that practice caught the single most severe finding of
the entire campaign.

## Fixed in this session (gate green)

### REVOKE-ENFORCE-001 — quorum revocation is NEVER enforced at admission (CRITICAL fail-open)
The `RevocationRegistry` (governance) is enacted by quorum and exported, but **no module on the admission path
ever consulted it** — `decide()` (kernel), `resolve()` (capabilities), and `PolarSeekNode.admit()` (planes)
contained no revocation check; `KernelInput` had no revocation field. A capability revoked by a full
governance quorum therefore **kept authorizing actions indefinitely** (until its own `notAfter` expiry). The
revocation mechanism was decorative. The dual-refuter gate dropped this candidate; manual verification (grep:
`isRevoked`/`RevocationRegistry` appear only in governance + tests + docs, never in kernel/resolver/node)
confirmed it. **Fix (preserves the stateless-kernel firewall):** revocation enters as an EXPLICIT, serializable
input — `KernelInput.revoked: readonly string[]` — exactly like the signed `observedAggregate` scalar, never as
in-kernel state. `decide()` passes it to `resolve()`, which denies a candidate whose chain contains a revoked
id. The field is omitted when empty, so a no-revocation admission encodes byte-identically (replay/receipt
hashes unchanged). `RevocationRegistry.revokedIds()` lets the caller source the list:
`node.admit({ ..., revoked: registry.revokedIds() })`.

### REVOKE-CHILD-002 — revoking a root would not have covered its delegated children (HIGH)
Folded into the same fix: `resolve()` checks **every link in the chain**, not just the tail, so revoking a
ROOT id denies every capability delegated from it — and a holder of a delegable root cannot re-delegate to a
fresh subject to outrun revocation (the new chain still contains the revoked root id). Regression tests: a
revoked id denies the capability at both `resolve()` and `node.admit()`; revoking a root denies its child;
revoking a child does not deny independent root use.

### VERIFY-CLI-001 — the external verifier CLI sourced BOTH trust anchors from the bundle (HIGH)
`tools/verify-receipt.mjs`. The library `verifyReceiptInclusion(receipt, witness, gossipedRoot, trustedIssuerKey)`
is **sound** — it requires the issuer key and gossiped root to be PINNED OUT OF BAND. The shipped CLI instead
read both from the same attacker-controlled bundle (`b.issuerPublicKeyHex`, `b.gossipedRootHex`), so the
issuer-key check was a self-comparison and the inclusion check verified against a root from the bundle. The
finder **ran the real CLI** on a fully forged, attacker-signed, self-rooted bundle for a $1M `allow` that was
never admitted — it printed "VERIFIED (no operator trust)", exit 0 — defeating the verifier's entire purpose.
(The same footgun class was fixed for `verifyGrant` earlier, but the receipt CLI was missed.) **Fix:** the CLI
now REQUIRES the issuer key + log root out of band (`NERION_ISSUER_PK`/`NERION_LOG_ROOT` env or argv) and
REFUSES to verify (exit 2, no PASS) otherwise; it never falls back to the bundle's own fields and surfaces a
NOTE when the bundle self-declares different anchors. `demo-bundle.mjs` prints the exact out-of-band command.

## Sound / positive assurance
- **ZK range proof (formal re-derivation):** SOUND on every axis — bit-sum binding (Σ commitments·2^i must
  equal the value commitment, BigInt weights), OR-proof challenge split (both sub-challenges cannot be chosen;
  the degenerate c=0/s=0 forgery is blocked), scalar reduction mod L + non-identity points, threshold folded
  into BOTH the FS hash and the verifier-recomputed cDiff, and the n≤251 cap is boundary-tight. No new break.
- **Concurrency/TOCTOU:** SOUND for the critical invariant — the OTS reserve-before-sign reads-and-burns the
  index in a single synchronous tick (no `await` between reservation and write), so no index reuse; gossip /
  chain / governance / settlement / translog state mutations are all synchronous. (One low note: the sealing
  provider has a check-then-act across an awaited KMS call, but `sign()` is synchronous and lock/revocation is
  not wired, so it is not exploitable.)
- **Rust hot-path:** ML-DSA sign/verify semantics match the @noble TS reference; all panics are on
  internally-generated data; no fail-open. (Hardening note for OSTIF/ROS: the cross-impl KAT covers only
  key-derivation, not a `(msg, sig)` verify vector — a future dep divergence could pass conformance silently.)

## Recorded residual (not fixed this round)
- **CONFORM-C10-001 (MED):** the C10 conformance check exercises equivocation/split-view detection using STHs
  with EMPTY signatures, so its green proves only same-size root de-duplication, not the signed/non-repudiable
  evidence the property requires (the repo's own contract says `detectEquivocation` callers must
  `verifyTreeHead` first). A conformant impl could ship split-view detection that accepts forged unsigned STHs.
  Hardening: C10 should sign the STHs and the detector path should require signature verification. Deferred to
  avoid colliding with the concurrent conformance-suite work; flagged for coordination.

## Method note
Two of this round's three fixes — including the CRITICAL revocation fail-open — were candidates the automated
dual-refuter gate returned as 0-confirmed. The standing practice of hand-verifying every finder summary
(rate-limited refuters force false negatives) has now caught a critical, a high, and a medium across Rounds 2b
through 4. Net campaign: deep crypto surfaces (ZK twice, KEM, OTS, constant-time, CBOR, Merkle) are sound;
the live defects were in the enforcement *wiring* (revocation, the verifier CLI, gossip ingress) rather than
the primitives.
