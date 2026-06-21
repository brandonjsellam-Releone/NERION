<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Team Apex — Round-5 audit (2026-06-21): final, composition & integration seams

**Scope:** the v:2 disclosure composition, attestation replay/freshness + the attest→session binding, the SDK
guard glue end-to-end, and kernel policy evaluation + a completeness-critic meta-pass. 4 surfaces, CHUNK=2,
dual-refuter, with the standing manual re-check of every finder summary. This round targeted the **seams**
between audited components — and that is exactly where the two findings were.

## Fixed in this session (gate green)

### SDK-REVOKE-001 — the SDK guard drops the revocation set (HIGH)
`sdks/ts/src/client.ts`. The REVOKE-ENFORCE-001 fix wired an explicit `revoked` input through
`node.admit()` → `decide()` → `resolve()`, but the SDK — `mcp.ts`'s "operational integration point for agents"
— provided no way to supply it: `GuardContext` had no `revoked` field and `PolarSeekClient.guard()` built the
`admit()` request omitting it. Since `admit()` only enforces revocation when `req.revoked` is non-empty, every
admission through `guardTool`/`guard` ran with no revocation set — so a revoked capability still authorized
actions **on the very path agents are told to use**. A fail-open at the composition seam of an otherwise-sound
fix. **Fix:** `GuardContext.revoked?: readonly string[]`, forwarded in `guard()` (mirroring `observedAggregate`).
Regression test: a revoked capability is denied through `guardTool`; the handler never runs.

## Handed off — architectural (dedicated task `task_a2464e51`)

### ATTEST-BIND-001 — the PermitToken MAC key is not bound to the attestation (HIGH)
`planes/src/node.ts`. The Plane-1 replay/identity defense (THREAT_MODEL M-P1-4 / §6) requires the permit MAC
key to be bound to a **fresh, verified** attestation. It is not: `admit()` never calls `appraise()`;
`Session.sessionKey` is a free `Bytes` field the caller fills, and the permit MAC derives straight from it.
A malicious agent (ADV-1) can construct a `Session` with an arbitrary `sessionKey` and chosen `claims`
(`sessionPublicKey` = a target capability's subject) **without any valid attestation**, and `admit()` mints a
permit an honest resource accepts (it derives its key from the same attacker-chosen `sessionKey`). The
appraisal hardening (nonce/expiry/N-of-M) is unreachable on the permit path; the canonical flows
(`demo-bundle.mjs`, conformance) appraise-then-discard or skip it entirely. **Why handed off, not rushed:** the
fix is an architectural change to the core admission flow with a genuine model decision — out-of-band-provisioned
session key (Scenario A: provisioning is the binding; document it) vs. attestation-derived short-lived key
(Scenario B: the intended model; derive `sessionKey` from a successful `AppraisalResult`, e.g. a gated
`mintSession()`/`admit(Evidence, AppraisalPolicy)` that fails closed on `!valid`). Done carefully with an ADR,
not as an end-of-window edit in the hottest concurrently-edited path. Full spec in the spawned task.

## Sound / positive assurance
- **v:2 disclosure composition:** beyond the known DISCLOSURE-SLOT-001, no exploitable composition-binding gap
  (the policy-satisfaction proof, Pedersen commitment, and selective-disclosure openings bind to the same
  commitment + threshold; the slot values never coincide in practice).
- **Policy evaluation:** `tierOf` prefix matching, denylist-before-resolve precedence, and `defaultTier` are
  fail-closed; no tier-downgrade path.
- **Completeness critic:** the top residual assurance gap it named IS ATTEST-BIND-001 (the attestation→session
  binding) — now recorded + handed off. The remaining gaps are the documented residuals (DISCLOSURE-SLOT-001,
  CUSTODY-AWS-AAD-001, CONFORM-C10-001, COSE-ALG-001) and the external-audit-only items (formal proofs, QROM,
  FIPS).

## Closing note
Across five rounds the live defects clustered at **integration seams and enforcement wiring** — revocation not
wired (kernel, then again at the SDK seam), the verifier CLI's trust anchors, gossip ingress, the
attestation→permit binding — while the cryptographic primitives (ZK twice, KEM, OTS, AEAD, Merkle, constant-time)
held under repeated adversarial attack. That is a healthy shape for a pre-external-audit codebase.
