// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * PermitToken binding & resource-side verification.
 *
 * Closes the headline Plane-1 replay risk: a PermitToken is bound to a specific
 * action (hash), audience (resource), session, and a tight expiry. A stolen
 * token cannot be replayed for a different action or at a different resource,
 * and is only valid briefly. (True single-use within the window is the
 * resource's idempotency responsibility — see docs/THREAT_MODEL.md M-P1-1.)
 */

import {
  encodeCanonical,
  SHA3_SHAKE256,
  issuePermit,
  verifyPermit,
  readPermit,
  deriveAudiencePermitKey,
  type Bytes,
  type PermitToken,
} from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { ActionIntent } from '../../capabilities/src/index.js'

/** Canonical commitment to the exact action a permit authorizes. */
export function actionHash(intent: ActionIntent): string {
  return bytesToHex(SHA3_SHAKE256.digest(encodeCanonical(intent)))
}

export interface PermitClaims {
  readonly sessionId: string
  readonly nonce: string
  readonly audience: string
  readonly actionHash: string
  readonly tier: number
  readonly exp: number
  readonly evaluator: string
  /** Kernel decision effect ('allow' | 'transform'), MAC-bound so a resource can
   *  enforce it from the permit alone and it cannot be silently downgraded. */
  readonly effect: string
}

/**
 * Issuer-side: mint a permit bound to `claims.audience`, MAC'd under the
 * audience-scoped key derived from the session secret. The issuer (kernel/node)
 * holds the session secret and derives per audience; each resource is
 * provisioned only with its own derived key, so a key-holding resource cannot
 * forge a permit for a different audience (PERMIT-001 / ADR-0015).
 */
export function issueBoundPermit(
  claims: PermitClaims,
  suite: string,
  sessionKey: Bytes,
): PermitToken {
  const audienceKey = deriveAudiencePermitKey(sessionKey, claims.audience)
  return issuePermit(claims, suite, audienceKey)
}

export interface PermitCheck {
  readonly audience: string
  readonly intent: ActionIntent
  readonly now: number
  readonly sessionId?: string
  /** When set, the permit's bound effect must equal this (e.g. the resource only
   *  honors 'allow', or requires 'transform'). */
  readonly expectedEffect?: string
}

export interface PermitVerdict {
  readonly ok: boolean
  readonly reasons: string[]
}

/**
 * Resource-side: verify a permit is valid AND bound to this exact action.
 *
 * `audienceKey` is THIS resource's audience-scoped key — the only permit key it
 * is provisioned with, `deriveAudiencePermitKey(sessionKey, itsAudience)`. It is
 * NOT the raw session secret: the MAC, not just the `audience` claim, now binds
 * the permit to this audience, so a permit minted for another audience fails the
 * MAC check here regardless of its claims (PERMIT-001 / ADR-0015). The
 * `audience` equality check below is retained as defense-in-depth.
 */
export function verifyPermitForAction(
  token: PermitToken,
  audienceKey: Bytes,
  check: PermitCheck,
): PermitVerdict {
  if (!verifyPermit(token, audienceKey)) {
    return { ok: false, reasons: ['permit MAC invalid (wrong audience key or tampered)'] }
  }
  const claims = readPermit(token) as PermitClaims
  const reasons: string[] = []
  if (claims.audience !== check.audience)
    reasons.push('permit audience does not match this resource')
  if (claims.actionHash !== actionHash(check.intent))
    reasons.push('permit is not bound to this action')
  // Fail closed on a missing/non-finite exp: such a permit must NOT be treated
  // as non-expiring (PS-PLANE-05).
  if (!(typeof claims.exp === 'number' && Number.isFinite(claims.exp) && check.now <= claims.exp)) {
    reasons.push('permit expired or has no valid expiry')
  }
  if (check.sessionId !== undefined && claims.sessionId !== check.sessionId) {
    reasons.push('permit session mismatch')
  }
  if (check.expectedEffect !== undefined && claims.effect !== check.expectedEffect) {
    reasons.push('permit effect does not match the expected effect')
  }
  return { ok: reasons.length === 0, reasons }
}
