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
import type { Bytes, KeyPair, PermitToken } from '../../crypto/src/index.js'
import { TransparencyLog, type InclusionWitness } from '../../translog/src/index.js'
import { buildReceipt, receiptLeaf, type Receipt } from '../../receipts/src/index.js'
import type { AttestationClaims } from '../../attest/src/index.js'
import { actionHash, issueBoundPermit, type PermitClaims } from './permit.js'

export interface Session {
  readonly sessionId: string
  /** Hot-path PermitToken MAC key, minted on successful attestation. */
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
      })
      const { index } = this.cfg.log.append(receiptLeaf(receipt))
      inclusion = this.cfg.log.proveInclusion(index)
      logRoot = this.cfg.log.root()
    }

    return { decision, permit, receipt, inclusion, logRoot }
  }
}
