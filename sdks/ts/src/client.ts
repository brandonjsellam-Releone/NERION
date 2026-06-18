/**
 * @polarseek/sdk (TypeScript) — the client agents and resources use.
 *
 * In Local/Private mode the client wraps an in-process PolarSeekNode. The same
 * surface will later target a remote node over a PQ-hybrid transport; callers
 * do not change.
 */

import type { ActionIntent, Capability } from '../../../capabilities/src/index.js'
import {
  PolarSeekNode,
  verifyPermitForAction,
  type AdmissionOutcome,
  type Session,
} from '../../../planes/src/index.js'

export interface GuardContext {
  readonly capabilities: readonly Capability[]
  readonly session: Session
  readonly audience: string
  readonly now: number
  readonly observedAggregate?: number
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
    return verifyPermitForAction(outcome.permit, ctx.session.sessionKey, {
      audience: ctx.audience,
      intent,
      now: ctx.now,
    }).ok
  }
}
