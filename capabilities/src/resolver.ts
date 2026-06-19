/**
 * Default-deny capability resolver.
 *
 * Given an action intent and a set of candidate capabilities, return the first
 * one that (a) verifies against the trusted roots, (b) is held by the requester,
 * and (c) authorizes the intent under EVERY grant in its chain. If none does,
 * the result is DENY. There is no ambient authority and no fallback to "allow".
 */

import { authorizesIntent } from './grant.js'
import { verifyChain, effectiveGrant } from './capability.js'
import type { Bytes } from '../../crypto/src/index.js'
import type { ActionIntent, Capability, EvalContext } from './types.js'

export interface ResolveResult {
  readonly authorized: boolean
  readonly capability: Capability | null
  readonly reason: string
}

const DENY = (reason: string): ResolveResult => ({ authorized: false, capability: null, reason })

export function resolve(
  intent: ActionIntent,
  candidates: readonly Capability[],
  trustedRoots: readonly Bytes[],
  ctx: EvalContext,
): ResolveResult {
  // Holder binding is mandatory: without an authenticated requester we cannot
  // bind a capability to its subject, so we fail closed (PS-CAP-03).
  if (ctx.holder === undefined) return DENY('requester holder identity is required')

  for (const cap of candidates) {
    if (!verifyChain(cap, trustedRoots)) continue

    // The requester must be the subject the capability was ultimately granted to.
    if (effectiveGrant(cap).subject !== ctx.holder) continue

    // Defense in depth: every grant in the chain must authorize the intent
    // (the tail is most-restrictive, but we check all).
    if (cap.chain.every((link) => authorizesIntent(link.grant, intent, ctx))) {
      return { authorized: true, capability: cap, reason: 'authorized by capability' }
    }
  }
  return DENY('no capability authorizes this action (default-deny)')
}
