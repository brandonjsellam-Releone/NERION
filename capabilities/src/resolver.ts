// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

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

// DOS-VERIFY-003 (Team Apex sweep): bound the candidate-capability count on the admission hot path.
// Each candidate costs up to MAX_CHAIN_LINKS ML-DSA-87 verifies in verifyChain; DOS-VERIFY-002 capped
// chain DEPTH but the candidate-array BREADTH was unbounded, so an attacker could force arbitrarily
// many PQ verifies per request (CPU-exhaustion DoS) even though the verdict still denies. A legitimate
// request presents only a handful of capabilities; this caps total verify cost at
// MAX_CANDIDATES * MAX_CHAIN_LINKS.
const MAX_CANDIDATES = 64

export function resolve(
  intent: ActionIntent,
  candidates: readonly Capability[],
  trustedRoots: readonly Bytes[],
  ctx: EvalContext,
  revoked: ReadonlySet<string> = new Set(),
): ResolveResult {
  // Holder binding is mandatory: without an authenticated requester we cannot
  // bind a capability to its subject, so we fail closed (PS-CAP-03).
  if (ctx.holder === undefined) return DENY('requester holder identity is required')
  if (candidates.length > MAX_CANDIDATES) {
    return DENY(`too many candidate capabilities (> ${MAX_CANDIDATES})`)
  }

  for (const cap of candidates) {
    if (!verifyChain(cap, trustedRoots)) continue

    // A revoked capability never authorizes — checked at EVERY chain link, not just
    // the tail, so revoking a ROOT id also denies every chain delegated from it (and
    // a holder cannot re-delegate to a fresh subject to outrun revocation). Governance
    // revocation enters as the explicit `revoked` input (REVOKE-ENFORCE-001 / -CHILD-002).
    if (cap.chain.some((link) => revoked.has(link.grant.id))) continue

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
