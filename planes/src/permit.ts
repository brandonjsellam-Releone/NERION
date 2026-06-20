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
}

export function issueBoundPermit(
  claims: PermitClaims,
  suite: string,
  sessionKey: Bytes,
): PermitToken {
  return issuePermit(claims, suite, sessionKey)
}

export interface PermitCheck {
  readonly audience: string
  readonly intent: ActionIntent
  readonly now: number
  readonly sessionId?: string
}

export interface PermitVerdict {
  readonly ok: boolean
  readonly reasons: string[]
}

/** Resource-side: verify a permit is valid AND bound to this exact action. */
export function verifyPermitForAction(
  token: PermitToken,
  sessionKey: Bytes,
  check: PermitCheck,
): PermitVerdict {
  if (!verifyPermit(token, sessionKey)) {
    return { ok: false, reasons: ['permit MAC invalid (wrong session key or tampered)'] }
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
  return { ok: reasons.length === 0, reasons }
}
