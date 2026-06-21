// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * PolarSeekNode — orchestrates the three planes for one admission request.
 *
 *   Plane 1 (hot):     stateless decide() -> bound PermitToken
 *   Plane 2 (nearline): for tiers that require it, a PQ receipt anchored to the
 *                       transparency log (synchronous for T2/T3 per the spec)
 *
 * The node holds no cross-decision state itself; the kernel is pure and the
 * transparency log is the only append-only store.
 */

import {
  decide,
  buildReplayBundle,
  replay,
  type Decision,
  type KernelInput,
  type Policy,
} from '../../kernel/src/index.js'
import type { ActionIntent, Capability } from '../../capabilities/src/index.js'
import { randomBytes, type Bytes, type KeyPair, type PermitToken } from '../../crypto/src/index.js'
import { TransparencyLog, type InclusionWitness } from '../../translog/src/index.js'
import {
  buildReceipt,
  receiptLeaf,
  INTENT_SALT_BYTES,
  type Receipt,
} from '../../receipts/src/index.js'
import type { AttestationClaims } from '../../attest/src/index.js'
import { actionHash, issueBoundPermit, type PermitClaims } from './permit.js'

export interface Session {
  readonly sessionId: string
  /**
   * Per-session secret, minted on successful attestation. The issuer derives a
   * per-audience PermitToken MAC key from this (`deriveAudiencePermitKey`); the
   * raw secret is held only by the issuer and never handed to a resource
   * (PERMIT-001 / ADR-0015).
   */
  readonly sessionKey: Bytes
  readonly claims: AttestationClaims
}

export interface NodeConfig {
  readonly suite: string
  readonly policy: Policy
  readonly trustedRoots: readonly Bytes[]
  readonly issuer: KeyPair
  readonly log: TransparencyLog
  readonly jurisdiction: string
  readonly permitTtlSeconds: number
}

export interface AdmissionRequest {
  readonly intent: ActionIntent
  readonly capabilities: readonly Capability[]
  readonly session: Session
  readonly audience: string
  readonly now: number
  readonly observedAggregate: number
}

export interface AdmissionOutcome {
  readonly decision: Decision
  readonly permit: PermitToken | null
  readonly receipt: Receipt | null
  readonly inclusion: InclusionWitness | null
  readonly logRoot: Bytes | null
}

export class PolarSeekNode {
  constructor(private readonly cfg: NodeConfig) {}

  admit(req: AdmissionRequest): AdmissionOutcome {
    const input: KernelInput = {
      intent: req.intent,
      capabilities: req.capabilities,
      policy: this.cfg.policy,
      trustedRoots: this.cfg.trustedRoots,
      now: req.now,
      observedAggregate: req.observedAggregate,
      holder: req.session.claims.sessionPublicKey,
    }

    const decision = decide(input)
    if (decision.effect === 'deny') {
      return { decision, permit: null, receipt: null, inclusion: null, logRoot: null }
    }

    const claims: PermitClaims = {
      sessionId: req.session.sessionId,
      nonce: req.session.claims.nonce,
      audience: req.audience,
      actionHash: actionHash(req.intent),
      tier: decision.tier,
      exp: req.now + this.cfg.permitTtlSeconds,
      evaluator: decision.evaluatorVersion,
      effect: decision.effect,
    }
    const permit = issueBoundPermit(claims, this.cfg.suite, req.session.sessionKey)

    // Nearline assurance: tiers requiring a receipt get one anchored now.
    let receipt: Receipt | null = null
    let inclusion: InclusionWitness | null = null
    let logRoot: Bytes | null = null
    if (decision.obligations.includes('nearline-receipt')) {
      const r = replay(buildReplayBundle(input))
      // Mint a fresh per‑receipt salt so the logged intent commitment is hiding
      // (RCPT‑001 / ADR‑0014). It rides out on receipt.intentSalt for the holder to
      // present to authorized verifiers; it is never written to the log leaf.
      const intentSalt = randomBytes(INTENT_SALT_BYTES)
      receipt = buildReceipt({
        suite: this.cfg.suite,
        evaluatorVersion: decision.evaluatorVersion,
        effect: decision.effect,
        tier: decision.tier,
        jurisdiction: this.cfg.jurisdiction,
        timestamp: req.now,
        intent: req.intent,
        capability: req.capabilities[0] ?? null,
        policy: this.cfg.policy,
        inputHash: r.inputHash,
        decisionHash: r.receiptHash,
        issuerSecretKey: this.cfg.issuer.secretKey,
        issuerPublicKey: this.cfg.issuer.publicKey,
        intentSalt,
      })
      const { index } = this.cfg.log.append(receiptLeaf(receipt))
      inclusion = this.cfg.log.proveInclusion(index)
      logRoot = this.cfg.log.root()
    }

    return { decision, permit, receipt, inclusion, logRoot }
  }
}
