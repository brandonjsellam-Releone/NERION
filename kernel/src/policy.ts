// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Deterministic risk-tiering and the pinned evaluator version.
 *
 * Tiering is a pure function of the explicit intent and policy — no clock, no
 * lookup, no randomness. The evaluator version is a hash binding the kernel
 * release to the exact policy, so a receipt records precisely what evaluated it.
 */

import { encodeCanonical, SHA3_SHAKE256 } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { ActionIntent, RiskTier } from '../../capabilities/src/index.js'
import type { Policy } from './types.js'

/** Bump on any change to the decision logic; bound into the evaluator version. */
export const KERNEL_VERSION = 'polarseek-kernel/0.1.0'

/**
 * Deterministic tier of an intent: first matching prefix wins, else default.
 *
 * Matching is SEGMENT-wise, not substring (PS-KERNEL-03): a rule prefix matches
 * only on an exact type or a dotted-namespace child, so `data.read` does not
 * under-tier a crafted `data.readX`.
 */
export function tierOf(intent: ActionIntent, policy: Policy): RiskTier {
  for (const rule of policy.tierRules) {
    const boundary = rule.prefix.endsWith('.') ? rule.prefix : rule.prefix + '.'
    if (intent.type === rule.prefix || intent.type.startsWith(boundary)) return rule.tier
  }
  return policy.defaultTier
}

/**
 * Pinned evaluator identity = hash over the kernel version + the canonical
 * policy. Two parties on the same kernel + policy compute the same id, and any
 * policy change is visible in every receipt.
 */
export function evaluatorVersion(policy: Policy): string {
  const id = SHA3_SHAKE256.digest(encodeCanonical([KERNEL_VERSION, policy]))
  return `${KERNEL_VERSION}+${bytesToHex(id).slice(0, 16)}`
}

/** A sensible default policy for the demo / tests (finance-flavored). */
export const DEFAULT_POLICY: Policy = {
  version: '0.1.0',
  tierRules: [
    { prefix: 'data.read', tier: 0 },
    { prefix: 'draft.', tier: 0 },
    { prefix: 'message.send', tier: 1 },
    { prefix: 'data.create', tier: 1 },
    { prefix: 'payment.', tier: 2 },
    { prefix: 'key.', tier: 2 },
    { prefix: 'data.delete', tier: 2 },
    { prefix: 'infra.deploy', tier: 2 },
    { prefix: 'actuation.physical', tier: 3 },
    { prefix: 'export.mass', tier: 3 },
    { prefix: 'model.weights', tier: 3 },
  ],
  denyActions: [],
  transformActions: [],
  defaultTier: 3,
}
