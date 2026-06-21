<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Team Apex — multi-round security audit campaign (2026-06-21)

An index of the in-repo adversarial audit campaign that preceded the external ROS / Trail of Bits audit. Each
round fanned out high-effort finders across the codebase, **refuted every candidate with two independent
skeptics** (an *exploitability* lens that must build a concrete proof-of-failure, and a *scope-and-novelty*
lens), and recorded only doubly-survived findings — **plus a manual re-check of every finder summary**, because
a refuter that dies to a transient burst rate-limit forces a false `is_real=false`. Per-round detail:
[round1](team-apex-round1-audit-2026-06-21.md) · [round2](team-apex-round2-audit-2026-06-21.md) ·
[round3](team-apex-round3-audit-2026-06-21.md) · [round4](team-apex-round4-audit-2026-06-21.md) ·
[zkrange/enforcement](team-apex-zkrange-2026-06-21.md) ·
[postfix-verification](team-apex-postfix-verification-2026-06-21.md).

All fixes are regression-tested; `npm run gate` (≈365 tests) and `npm run conformance` (23/23) green.

## Confirmed findings fixed (this campaign)

| ID | Sev | Surface | One-line | Where |
|---|---|---|---|---|
| REVOKE-ENFORCE-001 | **Critical** | admission | quorum revocation was NEVER consulted at admission (fail-open) — now an explicit `KernelInput.revoked` input enforced in `resolve()` | kernel/capabilities/planes/governance |
| KERNEL-TIME-001 | High | capabilities | non-finite `now` bypassed the validity window | `capabilities/src/grant.ts` |
| CAP-DELEG-001 | High | capabilities | `delegable:false` unenforced in chain verification (confused-deputy) | `capabilities/src/capability.ts` |
| ATTEST-FMT-001 | High | attest | appraisal gated/routed on the UNSIGNED `evidence.format` | `attest/src/software.ts` |
| MCP-TRANSFORM-001 | High | sdk | `guardTool` ran the handler un-transformed on a `transform` decision | `sdks/ts/src/mcp.ts` |
| GOV-QUORUM-001 | High | governance | approvals not bound to the quorum set → cross-quorum replay | `governance/src/quorum.ts` |
| LEDGER-EQUIV-001 | High | ledger | equivocation proof omitted same-height binding → slash honest validators | `ledger/src/chain.ts`,`equivocation.ts` |
| LEDGER-VRF-001 | High | ledger | negative/non-integer round grinds VRF sortition past the cert gate | `ledger/src/chain.ts` |
| GOSSIP-CENSOR-001 | High | ledger | unvalidated attestation pool → zero-stake censorship of finality | `ledger/src/gossip.ts` |
| RCPT-002 | High | receipts | `inputHash`/`decisionHash` re-leaked the amount the RCPT-001 salt hid | `receipts/src/receipt.ts` |
| REVOKE-CHILD-002 | High | capabilities | revoking a root would not cover its delegated children | `capabilities/src/resolver.ts` |
| VERIFY-CLI-001 | High | tools | external verifier read both trust anchors from the attacker bundle (forged → "VERIFIED") | `tools/verify-receipt.mjs` |
| GOSSIP-DOS-001 | Med | ledger | unbounded orphan-attestation pool | `ledger/src/gossip.ts` |
| LEDGER-PRECISION-002 | Med | ledger | view-change quorum check used IEEE-754 (high-stake flip) | `ledger/src/leader.ts` |
| SETTLE-METER-001 | Med | settlement | `meter()` had no `ref` idempotency → replayed permit drains a budget | `settlement/src/credits.ts` |
| SDK-REVOKE-001 | High | sdk | the SDK guard dropped the `revoked` set → revocation unenforced on the agent path | `sdks/ts/src/client.ts` |

**Open (handed off, architectural — `task_a2464e51`):** **ATTEST-BIND-001** (High) — the PermitToken MAC key
(`Session.sessionKey`) is not bound to a verified attestation; `admit()` never calls `appraise()`, so a
malicious agent can mint valid permits with a self-chosen session key and no real attestation. The fix is an
architectural model decision (out-of-band-provisioned vs. attestation-derived session key) + a gated
`mintSession()`/`admit(Evidence, policy)` — too central to rush at the window's end. Full spec in
[round5](team-apex-round5-audit-2026-06-21.md) and the spawned task.

(Parallel sessions independently fixed an overlapping set in the same window: RCPT-001, GOV-TIME/SUITE-001,
ATTEST-SUITE/TIME/NOFM-00x, SETTLE-001/002, LEDGER-PRECISION-001, ZKRANGE-002, CB-001, TLOG-001/002.)

**Pattern:** every *live* defect was in enforcement **wiring** — revocation never wired, the verifier CLI's
trust anchors, gossip ingress validation, a missed precision-fix site, receipt-field salting, permit-effect
gating — NOT in the cryptographic primitives.

## Sound under fresh adversarial attack (positive assurance)

- **ZK range/policy-satisfaction proofs** — re-derived formally TWICE (FS transcript completeness, bit-sum
  binding, OR-proof challenge split, scalar reduction + non-identity points, threshold binding, n≤251 cap). No
  new soundness break. *(Caveat unchanged: soundness is classical/ROM, labeled.)*
- **Hybrid KEM** — only audited noble X-Wing/QSF combiners; no Nerion-authored combine; the KEM shared secret
  has no production consumer (session keys are pre-shared, not KEM-derived).
- **HBS/LMS OTS custody** — no reserve-before-sign index reuse; the reservation reads-and-burns synchronously.
- **Constant-time** — `constantTimeEqual` guards every in-trust-model secret/auth comparison.
- **CBOR decode** — `maxDepth:1024`, no count pre-allocation, length-validated; no unauthenticated decode-DoS.
- **Merkle/translog** — second-preimage domain separation, no wrong-root forgery.
- **ops/env** — secrets never logged; no fail-open on missing config; no env value in a signed transcript.
- **Rust hot-path** — sign/verify semantics match the @noble TS reference; no fail-open.

## Documented residuals (latent / best-practice — not live fail-opens)

- **DISCLOSURE-SLOT-001** (med) — `commitField` lacks a per-slot context tag; not exploitable (the slot values
  never coincide); add `commitField(value, salt, context)` (coordinate with conformance C23).
- **CUSTODY-AWS-AAD-001** (med) — AWS KMS sealer binds no `EncryptionContext`; fix changes the pinned SigV4 KAT.
- **CONFORM-C10-001** (med) — the C10 equivocation check uses unsigned STHs; sign them + require `verifyTreeHead`.
- **COSE-ALG-001** (low) — `alg` hardcoded to ML-DSA-87, decoupled from `suite`; correct for all active suites.
- **Rust cross-impl KAT** — covers key-derivation but not a `(msg, sig)` verify vector.

## Honest framing

This was an internal multi-model adversarial campaign — it **accelerates** but does **not replace** the external
ROS / Trail of Bits audit. The constructions remain **UNAUDITED**; the residuals above are the recommended
starting backlog for the external review.
