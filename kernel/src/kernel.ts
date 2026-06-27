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

import {
  resolve,
  type Capability,
  type EvalContext,
  type RiskTier,
} from '../../capabilities/src/index.js'
import { tierOf, evaluatorVersion, KERNEL_VERSION } from './policy.js'
import { governedView, type GovernedIntent } from './blindness.js'
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

/** A decision plus the capability the resolver actually used to authorize it (null on deny). */
export interface DecisionWithAuthorizer {
  readonly decision: Decision
  readonly authorizingCapability: Capability | null
}

/**
 * KernelInput projected params-blind: the only shape the decision core ever sees. `intent` is a
 * {@link GovernedIntent} (perception payload `params` omitted), so decideCore cannot reference
 * `input.intent.params` — it is a compile error — and no raw full intent is in scope to reach
 * around it (GOV-PARAMS-BLINDNESS; see kernel/src/blindness.ts).
 */
type GovernedInput = Omit<KernelInput, 'intent'> & { readonly intent: GovernedIntent }

/**
 * The single safe-fallback deny: any unexpected condition denies at the highest tier rather than
 * throwing (fail-closed). Used both by {@link decideCore}'s body and by the params-blind projection
 * at the boundary in {@link decideWithAuthorizer}, so a throw in EITHER place produces a
 * byte-identical deny and never escapes the deny-by-default guarantee (PS-KERNEL-02).
 */
function safeFallbackDeny(message: string, evaluatorVersion: string): DecisionWithAuthorizer {
  return {
    decision: {
      effect: 'deny',
      tier: 3,
      reasons: [`safe-fallback deny: ${message}`],
      obligations: [],
      evaluatorVersion,
    },
    authorizingCapability: null,
  }
}

/**
 * The decision core: like {@link decide}, but ALSO returns the capability the resolver selected to
 * authorize the intent — the first candidate that verified and authorized, at ANY index. A receipt
 * must commit THIS capability, not the caller-supplied `capabilities[0]`, which the resolver is free
 * to skip (RECEIPT-CAP-001). One resolve; the returned `Decision` is byte-identical to `decide()`'s,
 * so the authorizer rides OUTSIDE the committed decision and changes no replay/receipt hash. A pure
 * function of the params-blind {@link GovernedInput}.
 */
function decideCore(input: GovernedInput): DecisionWithAuthorizer {
  // Computed inside the try so a policy that cannot be canonicalized fails
  // closed (deny) rather than throwing (PS-KERNEL-02).
  let ev = `${KERNEL_VERSION}+uncomputed`
  try {
    ev = evaluatorVersion(input.policy)
    const tier = tierOf(input.intent, input.policy)

    if (input.policy.denyActions.includes(input.intent.type)) {
      return {
        decision: {
          effect: 'deny',
          tier,
          reasons: ['action is on the policy denylist'],
          obligations: [],
          evaluatorVersion: ev,
        },
        authorizingCapability: null,
      }
    }

    const ctx: EvalContext = {
      now: input.now,
      tier,
      observedAggregate: input.observedAggregate,
      ...(input.holder !== undefined ? { holder: input.holder } : {}),
    }

    const res = resolve(
      input.intent,
      input.capabilities,
      input.trustedRoots,
      ctx,
      new Set(input.revoked ?? []),
    )
    if (!res.authorized) {
      return {
        decision: {
          effect: 'deny',
          tier,
          reasons: [res.reason],
          obligations: [],
          evaluatorVersion: ev,
        },
        authorizingCapability: null,
      }
    }

    const effect = input.policy.transformActions.includes(input.intent.type) ? 'transform' : 'allow'
    return {
      decision: {
        effect,
        tier,
        reasons: ['authorized by capability', `risk tier ${tier}`],
        obligations: obligationsForTier(tier),
        evaluatorVersion: ev,
      },
      authorizingCapability: res.capability,
    }
  } catch (e) {
    // Safe fallback: any unexpected condition denies at the highest tier.
    return safeFallbackDeny((e as Error).message, ev)
  }
}

/**
 * Like {@link decide}, but also returns the authorizing capability. The public entry point: it
 * projects the intent params-blind ONCE at the boundary and hands a {@link GovernedInput} to
 * {@link decideCore}, which never sees the raw intent — so the decision provably cannot read
 * `params` (GOV-PARAMS-BLINDNESS). Callers still pass the full intent; its `params` is hashed
 * into receipts elsewhere, never here.
 */
export function decideWithAuthorizer(input: KernelInput): DecisionWithAuthorizer {
  // FIX #5 (PS-KERNEL-02 hardening): the params-blind projection runs in argument-evaluation
  // position, OUTSIDE decideCore's try/catch. A throw here (e.g. a null/malformed intent whose
  // destructure in governedView throws) would otherwise bypass the deny-by-default guarantee.
  // Guard it so any unexpected condition at the boundary denies (fail-closed) rather than throws.
  // Valid inputs are unaffected: the projection succeeds and decideCore runs exactly as before.
  let governed: GovernedIntent
  try {
    governed = governedView(input.intent)
  } catch (e) {
    return safeFallbackDeny((e as Error).message, `${KERNEL_VERSION}+uncomputed`)
  }
  return decideCore({ ...input, intent: governed })
}

/** The decision alone — a pure function of the explicit input (see {@link decideWithAuthorizer}). */
export function decide(input: KernelInput): Decision {
  return decideWithAuthorizer(input).decision
}
