<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Team Apex — Round-1 broad surface audit (2026-06-21)

**Scope:** a throttled, full-surface adversarial sweep of the Nerion admission/enforcement + crypto code —
kernel, capabilities, crypto (suites/envelope/COSE/KEM/sign/code-sign), receipts+quorum, translog,
governance, disclosure (ZK/commitbind/selective), attest, keystore, sdks/MCP, ledger/settlement, and the
canonical-CBOR foundation. 14 surfaces, one high-effort finder each, **every candidate finding refuted by two
independent skeptics** (an *exploitability* lens that must build a concrete proof-of-failure, and a
*scope-and-novelty* lens that must confirm it is in-trust-model and not already-fixed/out-of-scope). Only
findings that survived **both** refuters are recorded.

**Outcome: 6 confirmed HIGH findings — 4 fixed + regression-tested in this session, 2 handed off** (they
change shared types/preimages that ripple into governance/ledger tests; spec'd for a dedicated session to
avoid a half-applied change while parallel sessions edit those modules). All other surfaces returned **sound,
zero findings**: the previously-fixed items (ZKRANGE-002, CB-001, PERMIT-001, RCPT-001, TLOG-001/2,
policyproof/quorum hardenings, `decide()` fail-closed) held under fresh attack.

## Fixed in this session (gate green)

### KERNEL-TIME-001 — non-finite `now` bypassed the capability validity-window (fail-open)
`capabilities/src/grant.ts` `authorizesIntent`. `now` is caller-supplied (the kernel reads no clock) and is
treated as adversarial — `tier`, `amount`, and `observedAggregate` each get a `Number.isSafeInteger` guard,
but `now` did not. With `now = NaN` (a JSON `null` coerced, `Number(undefined)`, a relay miscompute, or a
malicious caller), **both** `now < notBefore` and `now > notAfter` are `false`, so the window check is skipped
and an **expired or not-yet-valid** capability authorizes the action. **Fix:** `if (!Number.isSafeInteger(ctx.now)) return false`
before the window comparison, matching the adjacent guards. Regression test in `capabilities/test/capability.test.ts`
(expired grant + `NaN`/`Infinity` now ⇒ denied).

### CAP-DELEG-001 — `delegable:false` not enforced in chain verification (confused-deputy)
`capabilities/src/capability.ts` `verifyChain`. The prohibition lived only in the honest `attenuate()` helper;
`verifyChain` checked the child's attenuation but never that the **parent permitted onward delegation**. A
holder of a non-delegable capability could hand-craft a strictly-attenuating child for a fresh subject,
self-sign it (correct content-hash id + suite-bound signature), append it, and `verifyChain` accepted it —
spreading authority the issuer pinned to one holder. **Fix:** in the delegation-link (`i>0`) branch,
`if (!prev.grant.delegable) return false` before `isAttenuationOf`. (Chosen over editing `isAttenuationOf`,
which would have broken the `narrow()` attenuation property test.) Regression test: a strict onward delegation
under a non-delegable parent is rejected, while the identical construction under a delegable parent verifies.

### ATTEST-FMT-001 — appraisal gated/routed on the UNSIGNED `evidence.format` (fail-open)
`attest/src/software.ts` `appraise`. The signature binds only `evidence.claims`; the top-level
`evidence.format` is unsigned wire data. The policy-acceptance gate and the hardware-vs-software TEE routing
both keyed off `evidence.format`, so an attacker could take a genuine, validly-signed TEE quote
(`claims.format='tdx'`), relabel the envelope to `'software-dev'`, and the entire quote/measurement
verification block was skipped while the result still reported `claims.format='tdx'` downstream. **Fix:** route
acceptance + TEE verification off the **signed** `evidence.claims.format`, and reject any
envelope/claims format disagreement. Regression test: a relabeled-but-validly-signed quote fails closed with
"format mismatch".

### MCP-TRANSFORM-001 — `guardTool` ran the handler un-transformed on a `transform` decision (fail-open)
`sdks/ts/src/mcp.ts` `guardTool`. A `transform` decision means the action is admitted **only in modified form**
(e.g. a capped amount). The adapter only special-cased `deny`; for `transform` it fell through and invoked the
real handler with the **original** args, executing the un-attenuated action and returning `{allowed:true}`.
**Fix:** only invoke the handler when `effect === 'allow'`; for any other non-deny effect, return
`{allowed:false, reasons:['…transform obligation … handler not run']}` without running it. Regression test
(transform-policy node ⇒ handler never called, `allowed:false`).

## Also fixed in-session (the two ripple-heavy findings)

Both were initially scoped for a dedicated session (they change shared types/signing-preimages), then implemented
in-session with regression tests; `npm run gate` (365 tests) + `npm run conformance` (23/23) green.

### GOV-QUORUM-001 — `enact()` does not bind approvals to the quorum set/threshold — **FIXED**
Implemented: `quorumId = SHA3([GOV_CONTEXT,'quorum',sorted(members),threshold])` bound into the signed
`proposalBytes`; `approve()`/`verifyApproval()` now take the `quorum` and sign/verify over the bound bytes, so
an approval gathered under one committee no longer verifies (or counts) under another. Regression test:
cross-roster AND same-roster/lowered-threshold approvals yield `validApprovals: 0`.
`governance/src/quorum.ts`. `proposalBytes` signs `[GOV_CONTEXT,id,kind,target,payload,notBefore,notAfter,nonce]`
with **nothing about the Quorum** (`Quorum` carries no set-id). An approval gathered under a strict committee
Q1 is byte-identical and counts under any other quorum Q2 listing the same member — cross-quorum / set-
substitution consent transfer (acute under per-tier/per-epoch committees or a Q1→Q2 rotation). This is exactly
what ADR-0005 fixed in `receipts/src/quorum.ts` (`{setId,k,epoch,suite}` bound into the signed body); only the
`k>0` fail-closed back-port reached governance, not the set-binding. **Fix:** add `setId = SHA3(canonical([GOV_CONTEXT, sorted(members), threshold, epoch]))`
to `Quorum`; include it in `proposalBytes`; `approve()`/`verifyApproval()`/`enact()` sign+verify over the bound
bytes; `enact()` recomputes `setId` from its own trusted quorum and rejects a mismatch. + conformance case.

### LEDGER-EQUIV-001 — `verifyEquivocationProof` omits same-height binding (forged slashing) — **FIXED**
Root cause: `ledger/src/chain.ts attestMessage` bound only `(suite, hash)`, not height, so the equivocation
verifier (which has only hashes, not headers) could not tell a same-height double-sign from an honest
cross-height pair. Implemented: `attestMessage(suite, height, hash)` = `['polarseek-attest-v1', suite, height, hash]`;
`Attestation` gains a signature-bound `height`; `attest()` sets it; `verifyFinalized` requires
`a.height === block.header.height` and verifies under the bound height; `verifyEquivocationProof` now requires
`attA.height === attB.height` (and `proof.height` consistency). Regression test: two genuine attestations by one
validator at heights 0 and 1 are NOT a slashable equivocation; a true same-height double-sign still is.

## Method note

The two-refuter gate matters: several finder candidates on other surfaces were **killed** by the refuters as
already-fixed or out-of-scope (e.g. re-flagging the classical-ZK soundness label, or the TEE stubs that
correctly fail closed). Recording only doubly-survived findings keeps this list defensible for the external
ROS/ToB audit. None of the 6 is a regression of a prior fix; they are distinct residual holes.
