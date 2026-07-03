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

/**
 * Map an MCP-style tool call to a typed PolarSeek action intent.
 *
 * SECURITY CONTRACT (load-bearing — the whole adapter's guarantee reduces to this): the returned
 * intent MUST FAITHFULLY describe what `handler` will actually do — the same action `type`,
 * `resource`, `counterparty`, and `amount` the handler will execute. The kernel authorizes the
 * INTENT, not the handler; if `mapIntent` under-states the action (e.g. maps a large transfer to a
 * smaller `amount`, a different `resource`, or a benign `type`), the guard admits the understated
 * intent and then runs the real, over-authorized handler — a guard bypass by mis-mapping, not a
 * flaw in `guardTool`. `mapIntent` is the integrator's trusted boundary; keep it a pure, total,
 * faithful projection of the call (and validate `args` before mapping).
 */
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
  opts?: {
    /** Obligations the integrator has verifiably discharged OUT-OF-BAND (a dual-control approval, an
     *  n-of-m attestation quorum, a P3 co-sign). The guard fails closed on any obligation NOT in this
     *  set that it cannot itself evidence (see MCP-OBLIGATION-001 below). */
    readonly discharged?: readonly string[]
  },
): (toolName: string, args: A, ctx: GuardContext) => Promise<GuardedResult<R>> {
  const discharged = new Set(opts?.discharged ?? [])
  return async (toolName, args, ctx) => {
    // MCP-GUARD-THROW-001 (AAC cycle-5): `mapIntent` is the integrator's arg-validation boundary, and
    // its type `(toolName, args) => ActionIntent` gives it NO error channel — the only way it can
    // reject a malformed tool call is to THROW. An uncaught throw here would reject the returned
    // Promise instead of yielding `GuardedResult{allowed:false}`, violating this adapter's
    // "fails closed on malformed tool calls" contract and delegating the closed-vs-open decision to an
    // uncontrolled caller (a permissive dispatch-loop catch would turn it into a governance bypass).
    // Convert any mapping/validation throw into a structured tier-3 deny. The real `handler` (below) is
    // deliberately NOT wrapped — a genuine tool failure must propagate, not masquerade as a deny.
    let intent: ActionIntent
    try {
      intent = mapIntent(toolName, args)
    } catch (e) {
      const reasons = [
        `intent mapping / arg validation failed: ${e instanceof Error ? e.message : 'error'}`,
      ]
      return {
        allowed: false,
        result: null,
        decision: { effect: 'deny', tier: 3, reasons, obligations: [], evaluatorVersion: '' },
        receipt: null,
        reasons,
      }
    }
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
    // MCP-OBLIGATION-001 (AAC cycle-7 compound-failure review): the kernel decides per-tier obligations
    // (T2: 'step-up-approval'; T3: 'n-of-m-attestation' / 'dual-control' / 'all-planes') that
    // THREAT_MODEL M-P2-1 requires be discharged BEFORE the resource executes. The node self-fulfils
    // 'nearline-receipt' (evidenced by `receipt`) and 'session-attestation' is covered by the (attested)
    // session flow; every OTHER obligation needs an external discharge (dual control, n-of-m quorum, P3
    // co-sign) this reference adapter has no mechanism for. Running the handler anyway would over-
    // authorize a high-tier action with NONE of its controls (a fail-open seam: the obligations were
    // decided upstream but enforced by no downstream stage). So — exactly like the transform refusal
    // above — FAIL CLOSED; an integrator that discharged an obligation out-of-band passes it in
    // `opts.discharged`.
    const isDischarged = (o: string): boolean =>
      o === 'nearline-receipt' ? receipt != null : o === 'session-attestation' || discharged.has(o)
    const undischarged = outcome.decision.obligations.filter((o) => !isDischarged(o))
    if (undischarged.length > 0) {
      return {
        allowed: false,
        result: null,
        decision: outcome.decision,
        receipt,
        reasons: [
          `decision requires obligation(s) [${undischarged.join(', ')}] to be discharged before execution (THREAT_MODEL M-P2-1); the reference guard has no discharge mechanism, so the handler was NOT run`,
        ],
      }
    }

    const result = await handler(toolName, args)
    return { allowed: true, result, decision: outcome.decision, receipt, reasons: [] }
  }
}
