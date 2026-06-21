<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Team Apex — remaining-surface sweep (2026-06-21, continued)

A solo, council-driven (DeepSeek · Grok · Hermes · Gemini · OpenAI, lead-adjudicated) sweep of the modules
not covered by the round-1 broad audit or the post-fix verification round. Each module: independent-lineage
adversarial review → re-derive/adjudicate every claim (both directions) → fix + regression-test only the
genuine findings. Gate kept green throughout. Companion to
[team-apex-postfix-verification-2026-06-21.md](team-apex-postfix-verification-2026-06-21.md).

## Cleared SOUND (no code change)

- **`sdks/ts/mcp.ts` (`guardTool`, the actuator boundary).** Fail-closed: deny and `transform` both refuse
  to run the handler (MCP-TRANSFORM-001 fix in place), and the handler runs only after a resource-side
  `checkPermit` re-verification. *Adjudicated FALSE — DeepSeek "critical missing `await` on `checkPermit`":*
  `PolarSeekClient.checkPermit(...)` returns **`boolean`** (synchronous), so `!checkPermit(...)` is correct;
  the finding was explicitly conditional on an async `checkPermit` that does not exist. Grok + Hermes cleared.
- **`crypto/cose.ts` (COSE_Sign1 over ML-DSA).** Verify pins the protected header **byte-exactly** to
  `protectedHeader(expectedAlg)` and selects the algorithm from the out-of-band `suite` — alg substitution /
  downgrade / unprotected-header malleability all fail. *Adjudicated — producer-side `alg`-vs-`suite` mismatch
  (Hermes MEDIUM):* not verify-exploitable (DeepSeek + Grok refute) — the verifier never accepts a mismatched
  header; it is a producer-hygiene note, not a defect. C19 already exercises alg-binding.
- **`crypto/suites.ts` (SuiteID negotiation).** `negotiate()` considers only `active` suites (pending HQC /
  non-load-bearing FN excluded) and prefers Cat-5 (PS-5 pref 10 < PS-1 20); downgrade resistance comes from
  the SuiteID being bound into every signed/MAC'd transcript (envelope/permit/receipt/quorum). C1 covers it.
- **`ledger/leader.ts` (VRF eligibility + view-change cert).** `verifyViewChangeCert` binds
  `(suite, height, prevHash, certRound)` into both the per-vote filter and the signed `viewChangeMessage`,
  dedups validators, counts only positive-stake members, and requires `stake·3 ≥ 2·total` — no forged /
  cross-bound / under-threshold cert passes. `vrfAlpha` binds `(prevHash, round)`; `vrfLeaderEligible` is an
  unbiased stake-proportional draw over a 512-bit β.

## `ledger/gossip.ts` — **GOSSIP-BUFFER-001 found + fixed** (rest SOUND)

DeepSeek + Grok cleared the module as sound; Hermes raised five points — four refuted, one genuine:

- *Refuted — "cross-cert dedup / replay" (Hermes #1):* `verifyViewChangeCert` is a **stateless single-cert**
  verifier; each cert must independently reach ≥2/3 distinct valid signatures — overlapping certs accumulate
  nothing.
- *Refuted — "no slashing on double-attest" (#2):* honest nodes attest at most once per height (`attestedAt`);
  a byzantine double-attest is **recorded** (`observedConflicts`); slashing is `equivocation.ts`'s job (the
  spawned-task LEDGER-EQUIV module), not gossip's.
- *Refuted — "double-finalize at one height" (#3, claimed critical):* `ledger.submit` **advances the height**,
  so after a block finalizes at H the node is at H+1 and any other height-H block is stale
  (`block.height !== this.height()`) → single-finalization-per-height is **structural**, not just an
  under-1/3-byzantine property.
- *Refuted — "VRF replay across views" (#5):* `vrfAlpha` binds `prevHash`+`round`; the RFC 9381 proof (caller-
  verified; VRF-001-hardened) is over that α.
- **GOSSIP-BUFFER-001 (real, fixed) — #4.** The `+64` cap bounded the buffered height **range** but not the
  **count** of distinct blocks an adversary could flood at a single future height (each unique hash buffered —
  and re-flooded — without verification): an unbounded-memory / amplification vector, and the docstring's
  "bounds pendingBlocks against an adversarial flood" was a partial over-claim. **Fix:** a per-height cap
  (`MAX_PENDING_PER_HEIGHT = 64`) drops distinct blocks beyond it (no buffer, no re-flood), honest catch-up
  (a few blocks/height) unaffected; `pendingBlockCount()` accessor + `ledger/test/gossip-buffer.test.ts`
  (flood CAP+6 distinct future blocks → buffer bounded to CAP, then catch up and finalize normally). Low
  severity (in-process transport stand-in; a real transport also expires buffered blocks) but a real bound.

Gate green; `npm run conformance` → 23/23.

## Cleared — crypto remainder + foundational encoder test

A consolidated council pass (DeepSeek · Grok · Hermes — unanimous **REFUTED / ship**) over the remaining
low-logic crypto modules, plus a foundational-encoder hardening:

- **`crypto/cnsa.ts` (CNSA 2.0 oracle).** Per-component substring classification with the multi-tree
  (HSS/XMSS^MT) check ordered BEFORE the LMS/XMSS allow; ML-DSA-44/65 and ML-KEM-768 fall through to
  non-conformant. Inputs are internal SuiteIDs and the oracle is advisory evidence (not an enforcement gate),
  so a misclassification cannot flip a security decision. *Noted (not a defect):* the multi-tree regex would
  miss an exotic trailing-`_MT` SuiteID, but the authoritative `multiTree` flag (in `code-sign.ts` /
  `hbs-state.ts`) is the real guard, and broadening the regex risks false-positives on legit ids — left as-is.
- **`crypto/code-sign.ts`.** `assertSingleTree` rejects multi-tree via the `multiTree` flag **and** id/family
  regex; `getCodeSigner` throws for every id (no software LMS/XMSS — FIPS-module-only). No slip-through.
- **`crypto/kem.ts`.** Only hybrid KEMs registered (X-Wing, ML-KEM-1024+P-384) wrapping audited
  `@noble/post-quantum/hybrid`; the combiner is not re-implemented; HQC/unknown throw. No leg-drop / downgrade.
- **`crypto/cbor.ts` (foundational canonical encoder).** Thin `cbor2` dcbor wrapper; correctness is the
  library's (KAT-pinned, C4). **Hardening added:** `crypto/test/cbor-determinism.test.ts` exercises the
  load-bearing properties directly — deep (every-level) map key-order independence; byte-/round-trip-stability
  across large & negative integers, byte strings, unicode, empty structures, numeric Map keys; and injectivity
  over near-collision shapes (`{a:1}` vs `{a:1,b:2}`, `1` vs `"1"`, bytes vs array, `""` vs empty bytes). All
  hold — confirms the encoder is canonical + injective over the protocol's value space.
- **`ops/env.ts`.** Deployment-only `.env` loading (explicitly NOT protocol core; crypto/kernel/ledger read no
  env); secrets in a gitignored `.env`. Out of scope, sound.

## Sweep status — full surface covered

Every module has now been swept (this sweep + the post-fix round + round-1). Genuine finding fixed this sweep:
**GOSSIP-BUFFER-001**. Everything else cleared (often after refuting confident false positives). The two open
items — **GOV-QUORUM-001** and **LEDGER-EQUIV-001** — remain owned by their spawned-task sessions and were
deliberately not touched here.

## Hardening phase — property-based confidence for the dominant audit-risk component

With the surface swept, added randomized confidence where it matters most for the external ZK audit:

- **`disclosure/test/zkrange.property.test.ts` (fast-check).** Property coverage of the range / policy-
  satisfaction proofs complementing the example tests: **completeness** (any `amount < threshold` verifies,
  and is bound to `n`), **soundness** (an honest prover cannot build a proof for `amount ≥ threshold` — it
  throws), and **binding** (a valid proof fails against a wrong threshold / commitment blinding / committed
  amount). Plus a policyproof property (proves **iff** `amount ≤ ceiling`, bound to its commitment). Run at
  n=16 with bounded `numRuns` so the gate stays tractable; all properties hold across random inputs.

- **Concurrent-change maintenance.** A parallel session landed **ATTEST-SUITE-001** (the evidence signature is
  now suite-bound + domain-separated, `encodeCanonical([ctx, suite, claims])`) and **ATTEST-NOFM-002**
  (positive-`n` guard) on top of the ATTEST-TIME-001/NOFM-001 fixes — and a parallel **GOSSIP-DOS-001**
  (attestation-pool cap) on top of GOSSIP-BUFFER-001. Those signature changes broke two evidence-hand-crafting
  tests (`attest/test/verifiers.test.ts`, `attest/test/attest-hardening.test.ts`); both updated to sign over
  the new suite-bound message. Combined tree green.

## Cross-layer composition review — **AGG-001 found (architectural; documented + flagged)**

The per-module sweep is complete, so the last angle is the gaps *between* layers (admission → permit → receipt
→ verification). Council: Grok · Hermes · OpenAI — **unanimous on AGG-001**.

- **AGG-001 (aggregate-cap integrity, MEDIUM-HIGH) — the rolling `aggregateCap` is enforced against an
  UNVERIFIED, caller-supplied `observedAggregate`.** It is documented throughout (`kernel/types.ts`,
  `capabilities/types.ts`) as "the signed scalar / externally computed and signed," but its type is a bare
  `number`: there is **no signature field and no verification** — not in the pure kernel (correctly), not in
  `planes/node.ts admit()`, and the SDK `client.guard` does **`observedAggregate: ctx.observedAggregate ?? 0`**
  with `observedAggregate?` *optional and undocumented*. So **omitting it silently disables the rolling cap**
  (defaults to 0), and a caller that can influence the `GuardContext` can understate it to exceed the cap. The
  pure-kernel design is correct; the gap is the missing attestation/verification at the admission boundary.
  - *Adjudication:* confirmed real and consistent with the "signed scalar" docs being aspirational, not
    enforced. It is **architectural** (a verified `AggregateAttestation` type + admission-side verification, or
    a kernel-level *conditional* fail-closed when an `aggregateCap` applies but no aggregate is supplied) and
    sits in heavily-churned, concurrently-edited files (`client.ts` / `node.ts` / `grant.ts`). Per the same
    discipline applied to the other architectural findings (GOV-QUORUM-001, LEDGER-EQUIV-001 — handed off, not
    hot-patched), it is **documented + flagged** here rather than hastily patched into the churning tree.
    Immediate mitigation landed: a loud TRUST-BOUNDARY warning on `GuardContext.observedAggregate` so an
    integrator can't omit it (silently disabling the cap) unknowingly. Full fix = verified attestation at
    admission, OR `guard()` requiring `observedAggregate` whenever any in-scope capability sets `aggregateCap`.
  - *OpenAI also noted* a rolling-cap **TOCTOU** (two concurrent admits both see the same aggregate and each
    pass): inherent to the stateless-kernel + external-aggregate design — the nearline plane must reserve
    atomically. A design note, not a code defect in the current modules.

- *Adjudicated lower-priority / refuted:* **permit↔receipt are not cryptographically tied to each other** (only
  independently to the same intent + decision) — Grok refuted as low-value (both already bind the intent and
  the decision chain within one `admit()`); raising it would matter only for a "this receipt came from this
  permit" proof, a different threat model. **Cross-decision replay of identical intents** is the documented
  resource-side idempotency responsibility (`permit.ts` docstring) plus permit `exp`/`nonce`/`audience` binding.

Gate green at 365 tests; `npm run conformance` → 23/23.
