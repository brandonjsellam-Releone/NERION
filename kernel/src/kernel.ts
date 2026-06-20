// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * The admission kernel: a pure, deterministic decision function.
 *
 *   decide(input) -> { allow | deny | transform }
 *
 * Properties (verified by tests in kernel/test and modeled in kernel/spec):
 *  - Deterministic: same input -> byte-identical decision.
 *  - Default-deny / fail-closed: anything not positively authorized is denied,
 *    and any unexpected condition denies (never fails open).
 *  - Receipt-implies-authorization: an `allow` is returned only when a verified
 *    capability authorized the intent.
 *  - Holds no state across decisions; reads no clock; performs no I/O.
 */

import { resolve, type EvalContext, type RiskTier } from '../../capabilities/src/index.js'
import { tierOf, evaluatorVersion, KERNEL_VERSION } from './policy.js'
import type { Decision, KernelInput } from './types.js'

function obligationsForTier(tier: RiskTier): string[] {
  switch (tier) {
    case 0:
      return []
    case 1:
      return ['session-attestation']
    case 2:
      return ['nearline-receipt', 'step-up-approval']
    case 3:
      return ['nearline-receipt', 'n-of-m-attestation', 'dual-control', 'all-planes']
  }
}

export function decide(input: KernelInput): Decision {
  // Computed inside the try so a policy that cannot be canonicalized fails
  // closed (deny) rather than throwing (PS-KERNEL-02).
  let ev = `${KERNEL_VERSION}+uncomputed`
  try {
    ev = evaluatorVersion(input.policy)
    const tier = tierOf(input.intent, input.policy)

    if (input.policy.denyActions.includes(input.intent.type)) {
      return {
        effect: 'deny',
        tier,
        reasons: ['action is on the policy denylist'],
        obligations: [],
        evaluatorVersion: ev,
      }
    }

    const ctx: EvalContext = {
      now: input.now,
      tier,
      observedAggregate: input.observedAggregate,
      ...(input.holder !== undefined ? { holder: input.holder } : {}),
    }

    const res = resolve(input.intent, input.capabilities, input.trustedRoots, ctx)
    if (!res.authorized) {
      return { effect: 'deny', tier, reasons: [res.reason], obligations: [], evaluatorVersion: ev }
    }

    const effect = input.policy.transformActions.includes(input.intent.type) ? 'transform' : 'allow'
    return {
      effect,
      tier,
      reasons: ['authorized by capability', `risk tier ${tier}`],
      obligations: obligationsForTier(tier),
      evaluatorVersion: ev,
    }
  } catch (e) {
    // Safe fallback: any unexpected condition denies at the highest tier.
    return {
      effect: 'deny',
      tier: 3,
      reasons: [`safe-fallback deny: ${(e as Error).message}`],
      obligations: [],
      evaluatorVersion: ev,
    }
  }
}
