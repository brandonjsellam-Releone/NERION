// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/kernel — the stateless, deterministic admission kernel.
 *
 * Govern the verb, never the eye. Pure function of explicit inputs; no
 * cross-decision state, no clock, no I/O; default-deny and fail-closed.
 */

export type { Effect, TierRule, Policy, KernelInput, Decision } from './types.js'
export { KERNEL_VERSION, tierOf, evaluatorVersion, DEFAULT_POLICY } from './policy.js'
export { decide, decideWithAuthorizer } from './kernel.js'
export type { DecisionWithAuthorizer } from './kernel.js'
export { buildReplayBundle, replay } from './replay.js'
export type { ReplayBundle, ReplayResult } from './replay.js'
export {
  expectedRiskClass,
  expectedPolicyBinding,
  checkManifestConsistency,
  assertManifestConsistent,
} from './manifest-bind.js'
export type { ManifestConsistency } from './manifest-bind.js'
