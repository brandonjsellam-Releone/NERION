// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/sdk (TypeScript) — the client agents and resources use.
 *
 * In Local/Private mode the client wraps an in-process PolarSeekNode. The same
 * surface will later target a remote node over a PQ-hybrid transport; callers
 * do not change.
 */

import type { ActionIntent, Capability } from '../../../capabilities/src/index.js'
import type { Bytes } from '../../../crypto/src/index.js'
import {
  PolarSeekNode,
  verifyPermitForAction,
  deriveAudiencePermitKey,
  type AdmissionOutcome,
  type Session,
} from '../../../planes/src/index.js'

export interface GuardContext {
  readonly capabilities: readonly Capability[]
  readonly session: Session
  readonly audience: string
  readonly now: number
  readonly observedAggregate?: number
  /**
   * A standalone (out-of-process) resource is provisioned with ONLY its
   * audience-scoped key, `deriveAudiencePermitKey(sessionKey, audience)`, never
   * the raw session secret (PERMIT-001 / ADR-0015). When set, `checkPermit`
   * verifies under it. In single-process Local mode (one trust domain) it is
   * omitted and the key is derived on the fly from the in-process session.
   */
  readonly audienceKey?: Bytes
}

export class PolarSeekClient {
  constructor(private readonly node: PolarSeekNode) {}

  /** Run an action intent through admission; returns the full outcome. */
  guard(intent: ActionIntent, ctx: GuardContext): AdmissionOutcome {
    return this.node.admit({
      intent,
      capabilities: ctx.capabilities,
      session: ctx.session,
      audience: ctx.audience,
      now: ctx.now,
      observedAggregate: ctx.observedAggregate ?? 0,
    })
  }

  /**
   * Resource-side gate: confirm a permit authorizes THIS exact action before
   * the resource executes it (defense in depth against a replayed/forged permit).
   */
  checkPermit(outcome: AdmissionOutcome, ctx: GuardContext, intent: ActionIntent): boolean {
    if (outcome.permit === null) return false
    const audienceKey =
      ctx.audienceKey ?? deriveAudiencePermitKey(ctx.session.sessionKey, ctx.audience)
    return verifyPermitForAction(outcome.permit, audienceKey, {
      audience: ctx.audience,
      intent,
      now: ctx.now,
    }).ok
  }
}
