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
  /**
   * The rolling aggregate already consumed toward any capability `aggregateCap`.
   * TRUST BOUNDARY (AGG-001, Team Apex 2026-06-21): the (pure) kernel enforces the
   * aggregate cap against this value but CANNOT verify it, and it is NOT a
   * signed/attested type — so the cap is only as trustworthy as whoever supplies
   * this number. **Omitting it defaults to 0 in `guard()`, which silently DISABLES
   * the rolling cap.** A deployment that relies on `aggregateCap` MUST source this
   * from a trusted nearline plane (ideally a signed attestation the admission layer
   * verifies) and NEVER from the untrusted agent. Full remediation = a verified
   * `AggregateAttestation` at admission (roadmapped, architectural — like the
   * spawned GOV-QUORUM-001 / LEDGER-EQUIV-001 fixes).
   */
  readonly observedAggregate?: number
  /**
   * Capability ids revoked by governance — forwarded to admission so a revoked
   * capability is denied on the agent integration path too. WITHOUT this, the
   * REVOKE-ENFORCE-001 kernel fix is unreachable through the SDK (SDK-REVOKE-001,
   * Team Apex 2026-06-21). Source it per call from `registry.revokedIds()`.
   */
  readonly revoked?: readonly string[]
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
      // Forward the revocation set so revocation is enforced on the agent path too
      // (SDK-REVOKE-001). Conditional so a no-revocation call stays unchanged.
      ...(ctx.revoked && ctx.revoked.length > 0 ? { revoked: ctx.revoked } : {}),
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
