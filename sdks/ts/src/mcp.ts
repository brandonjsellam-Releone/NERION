// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * MCP / tool-call adapter.
 *
 * Wraps a high-risk agent tool handler (payments, infra changes, data
 * export/delete, code deploy, key rotation, …) so the action is ADMITTED — and
 * the issued PermitToken re-verified at the resource — before it executes. A
 * denied action never runs; an allowed action runs and yields its receipt for
 * audit. This is the operational integration point for agents.
 */

import type { ActionIntent } from '../../../capabilities/src/index.js'
import type { AdmissionOutcome } from '../../../planes/src/index.js'
import type { Receipt } from '../../../receipts/src/index.js'
import type { PolarSeekClient, GuardContext } from './client.js'

/** Map an MCP-style tool call to a typed PolarSeek action intent. */
export type IntentMapper<A> = (toolName: string, args: A) => ActionIntent

export interface GuardedResult<R> {
  readonly allowed: boolean
  readonly result: R | null
  readonly decision: AdmissionOutcome['decision']
  readonly receipt: Receipt | null
  readonly reasons: string[]
}

/**
 * Produce a guarded version of a tool handler. The returned function admits the
 * call, re-checks the permit at the resource boundary, and only then invokes
 * the real handler. `effect: 'transform'` is treated as allowed but flags the
 * obligation for the caller to apply the transform.
 */
export function guardTool<A, R>(
  client: PolarSeekClient,
  mapIntent: IntentMapper<A>,
  handler: (toolName: string, args: A) => R | Promise<R>,
): (toolName: string, args: A, ctx: GuardContext) => Promise<GuardedResult<R>> {
  return async (toolName, args, ctx) => {
    const intent = mapIntent(toolName, args)
    const outcome = client.guard(intent, ctx)
    const receipt = outcome.receipt

    if (outcome.decision.effect === 'deny') {
      return {
        allowed: false,
        result: null,
        decision: outcome.decision,
        receipt,
        reasons: [...outcome.decision.reasons],
      }
    }
    // A 'transform' decision admits the action ONLY in modified form (e.g. a
    // capped amount or a redacted field). The kernel returns the obligation, not
    // a rewritten intent, and this reference adapter has no transform applier —
    // so invoking the handler with the ORIGINAL args would execute the
    // un-attenuated, over-authorized action. Refuse to run it rather than
    // silently over-authorize (MCP-TRANSFORM-001, Team Apex 2026-06-21). An
    // integrator that can apply the obligation should re-submit a modified intent
    // that the kernel admits as 'allow'.
    if (outcome.decision.effect !== 'allow') {
      return {
        allowed: false,
        result: null,
        decision: outcome.decision,
        receipt,
        reasons: [
          `effect "${outcome.decision.effect}" requires the transform obligation to be applied before execution; handler not run`,
        ],
      }
    }
    if (!client.checkPermit(outcome, ctx, intent)) {
      return {
        allowed: false,
        result: null,
        decision: outcome.decision,
        receipt,
        reasons: ['permit failed resource-side verification'],
      }
    }

    const result = await handler(toolName, args)
    return { allowed: true, result, decision: outcome.decision, receipt, reasons: [] }
  }
}
