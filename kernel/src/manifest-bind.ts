// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * GOV-MANIFEST-BIND — bind the declared Action-Manifest to the ENFORCED decision.
 *
 * The Action Manifest (ADR-0025 / ADR-0030, the EU-AI-Act Article-13 audit-legibility surface) is a
 * projection that *self-asserts* a `riskClass` (T0..T3) and a `policyHash`. Nothing today checks that
 * the declared risk class matches the tier the kernel actually applies, or that the declared policy
 * matches the policy the kernel actually evaluated under — so a deployer could present a manifest that
 * understates the applied tier (verbId↔tier "semantic laundering", flagged in docs/FRONTIER.md).
 *
 * This module adds a PURE consistency predicate:
 *   - `manifest.riskClass` MUST equal `T${tierOf(intent, policy)}` — the tier the kernel applies.
 *   - `manifest.policyHash` MUST equal a domain-separated canonical hash of the policy. This is
 *     deliberately KERNEL-VERSION-INDEPENDENT (council fix): a kernel upgrade with an unchanged
 *     policy must NOT invalidate manifests. The kernel's own identity is carried separately by the
 *     receipt's `evaluatorVersion`, so manifest and receipt stay mutually consistent by derivation
 *     from the same policy, without coupling the manifest to the kernel build.
 *
 * SCOPE (honest): this binds the declared TIER and POLICY identity, so it closes verbId↔TIER
 * "semantic laundering". It does NOT bind the allow/deny/transform EFFECT — the manifest carries no
 * effect field today, and adding one is a wire-affecting manifest-schema change (a documented
 * follow-up), so within-tier effect laundering is out of scope here.
 *
 * Additive and OPTIONAL: the kernel does not call this on the decision path (it stays a pure,
 * params-blind function). It is currently an optional audit-consistency check — it reduces the
 * laundering surface only once wired into permit issuance / verification (the follow-up). No wire
 * format, no KAT, no `Ps1` change, no cross-decision state. The manifest is a projection computed
 * after admission, so this is defense-in-depth / audit-legibility, NOT a core security boundary —
 * and purely a TECHNICAL ALIGNMENT with EU-AI-Act Article 13, never a "compliant AI system" claim.
 */

import { encodeCanonical, SHA3_SHAKE256 } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import { tierOf } from './policy.js'
import type { Policy } from './types.js'
import type { ActionIntent } from '../../capabilities/src/index.js'
import type { ActionManifest, RiskClass } from '../../capabilities/src/profile.js'

/** Domain-separated, kernel-version-independent policy identity for the manifest binding. */
const POLICY_ID_CTX = 'nerion/policy-id/v1'

/** The risk class the kernel actually applies to `intent` under `policy` (T0..T3). */
export function expectedRiskClass(intent: ActionIntent, policy: Policy): RiskClass {
  return `T${tierOf(intent, policy)}` as RiskClass
}

/**
 * The canonical policy identity a consistent manifest's `policyHash` must carry: a domain-separated
 * SHA3-256 over the canonical policy, KERNEL-VERSION-INDEPENDENT (council fix) so a kernel upgrade
 * with an unchanged policy does not invalidate manifests. The kernel separately carries its own
 * identity in the receipt's `evaluatorVersion`.
 */
export function expectedPolicyBinding(policy: Policy): string {
  return bytesToHex(SHA3_SHAKE256.digest(encodeCanonical([POLICY_ID_CTX, policy])))
}

export interface ManifestConsistency {
  readonly consistent: boolean
  /** Human-readable mismatch descriptions (empty iff consistent). */
  readonly mismatches: readonly string[]
}

/**
 * Check that a manifest's declared `riskClass` and `policyHash` match the decision the kernel would
 * actually make for `intent` under `policy`. Pure, total, never throws.
 */
export function checkManifestConsistency(
  manifest: ActionManifest,
  intent: ActionIntent,
  policy: Policy,
): ManifestConsistency {
  const mismatches: string[] = []

  const wantRisk = expectedRiskClass(intent, policy)
  if (manifest.riskClass !== wantRisk) {
    mismatches.push(
      `riskClass: manifest declares ${manifest.riskClass} but the applied tier is ${wantRisk}`,
    )
  }

  const wantPolicy = expectedPolicyBinding(policy)
  if (manifest.policyHash !== wantPolicy) {
    mismatches.push(
      `policyHash: manifest declares "${manifest.policyHash}" but the evaluator identity is "${wantPolicy}"`,
    )
  }

  return { consistent: mismatches.length === 0, mismatches }
}

/** Throwing form of {@link checkManifestConsistency} for use as a permit-issue / verify gate. */
export function assertManifestConsistent(
  manifest: ActionManifest,
  intent: ActionIntent,
  policy: Policy,
): void {
  const r = checkManifestConsistency(manifest, intent, policy)
  if (!r.consistent) {
    throw new Error(`manifest inconsistent with the applied decision: ${r.mismatches.join('; ')}`)
  }
}
