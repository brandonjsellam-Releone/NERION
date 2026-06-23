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
  decideWithAuthorizer,
  buildReplayBundle,
  replay,
  evaluatorVersion,
  type Decision,
  type KernelInput,
  type Policy,
} from '../../kernel/src/index.js'
import type { ActionIntent, Capability } from '../../capabilities/src/index.js'
import {
  randomBytes,
  HKDF_SHA384,
  encodeCanonical,
  constantTimeEqual,
  type Bytes,
  type KeyPair,
  type PermitToken,
} from '../../crypto/src/index.js'
import { TransparencyLog, type InclusionWitness } from '../../translog/src/index.js'
import {
  buildReceipt,
  receiptLeaf,
  INTENT_SALT_BYTES,
  type Receipt,
} from '../../receipts/src/index.js'
import {
  appraise,
  type AttestationClaims,
  type Evidence,
  type AppraisalPolicy,
} from '../../attest/src/index.js'
import { actionHash, issueBoundPermit, type PermitClaims } from './permit.js'

const SESSION_KDF_CONTEXT = 'polarseek/session-key/v1'

/**
 * Derive a session secret from the node's root secret + the VERIFIED attestation
 * claims. Possessing a session key that admission accepts then PROVES a successful,
 * fresh appraisal happened (THREAT_MODEL M-P1-4) — the root secret never leaves the
 * node, so a caller cannot fabricate an accepted session (ATTEST-BIND-001, Team Apex
 * 2026-06-21). HKDF-SHA-384 over the canonical claims; output is the 48-byte MAC key.
 */
function deriveSessionKey(rootSecret: Bytes, claims: AttestationClaims): Bytes {
  const info = encodeCanonical([SESSION_KDF_CONTEXT, claims])
  return HKDF_SHA384.derive(rootSecret, new Uint8Array(0), info, 48)
}

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
  /**
   * Optional node root secret for deriving attestation-bound session keys
   * (`establishSession` / `requireAttestedSession`, ATTEST-BIND-001). Held only by
   * the node; never handed to a resource.
   */
  readonly sessionRootSecret?: Bytes
  /**
   * When true, `admit()` DENIES any session whose `sessionKey` was not derived by
   * THIS node from a verified attestation (i.e. not produced by `establishSession`),
   * closing the gap where a fabricated session with a self-chosen key mints a valid
   * permit (ATTEST-BIND-001). Default false preserves the in-process / out-of-band-
   * provisioned model. Production deployments in the dynamic attestation model SHOULD
   * set this and mint sessions via `establishSession`.
   */
  readonly requireAttestedSession?: boolean
}

export interface AdmissionRequest {
  readonly intent: ActionIntent
  readonly capabilities: readonly Capability[]
  readonly session: Session
  readonly audience: string
  readonly now: number
  readonly observedAggregate: number
  /**
   * Capability ids revoked by governance (the explicit revocation input). The
   * caller sources these from its `RevocationRegistry` (`revokedIds()`); a
   * candidate whose chain contains a revoked id is denied at admission
   * (REVOKE-ENFORCE-001, Team Apex 2026-06-21). Omit/empty when none are revoked.
   */
  readonly revoked?: readonly string[]
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
    // ATTEST-BIND-001: when required, the session secret must be one THIS node derived
    // from a verified attestation (via establishSession). Otherwise a caller could
    // fabricate a Session with a self-chosen key + claims and mint a valid permit.
    if (this.cfg.requireAttestedSession) {
      const denied = this.checkAttestedSession(req.session, req.now)
      if (denied) return denied
    }

    const input: KernelInput = {
      intent: req.intent,
      capabilities: req.capabilities,
      policy: this.cfg.policy,
      trustedRoots: this.cfg.trustedRoots,
      now: req.now,
      observedAggregate: req.observedAggregate,
      holder: req.session.claims.sessionPublicKey,
      // Include only when non-empty so a no-revocation admission encodes byte-
      // identically to before (replay/receipt hashes unchanged) — REVOKE-ENFORCE-001.
      ...(req.revoked && req.revoked.length > 0 ? { revoked: req.revoked } : {}),
    }

    const { decision, authorizingCapability } = decideWithAuthorizer(input)
    if (decision.effect === 'deny') {
      return { decision, permit: null, receipt: null, inclusion: null, logRoot: null }
    }

    const claims: PermitClaims = {
      sessionId: req.session.sessionId,
      nonce: req.session.claims.nonce,
      audience: req.audience,
      actionHash: actionHash(req.intent),
      tier: decision.tier,
      // PERMIT-EXP-CLAMP (Team Apex sweep): a permit must not OUTLIVE the attestation freshness that
      // authorized its session. Without the clamp, a permit minted just before the session's
      // attestation `notAfter` stays honored for the full TTL past it, extending the very window
      // ATTEST-EXP-001 enforces at admit time (defeating re-attestation / revocation for up to one
      // TTL). Clamp to the (finite) attestation notAfter; a non-finite notAfter keeps the plain TTL
      // (an attested session with a non-finite notAfter is already rejected by checkAttestedSession).
      exp: Number.isSafeInteger(req.session.claims.notAfter)
        ? Math.min(req.now + this.cfg.permitTtlSeconds, req.session.claims.notAfter)
        : req.now + this.cfg.permitTtlSeconds,
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
        // RECEIPT-CAP-001: commit the capability the resolver ACTUALLY used, not caller-array[0]
        // (which the resolver may skip), so the receipt's authorizing-capability commitment is
        // truthful. Identical to capabilities[0] in the common single-capability case.
        capability: authorizingCapability,
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

  /**
   * Establish a session from VERIFIED attestation evidence: appraise it (fail closed
   * on an invalid / forged / stale attestation) and derive the session secret from the
   * verified claims, so a fabricated session cannot mint a usable permit
   * (ATTEST-BIND-001). The resource still only ever receives
   * `deriveAudiencePermitKey(sessionKey, audience)`, never the root secret.
   */
  establishSession(
    evidence: Evidence,
    appraisalPolicy: AppraisalPolicy,
    sessionId?: string,
  ): Session {
    if (this.cfg.sessionRootSecret === undefined) {
      throw new Error('establishSession requires NodeConfig.sessionRootSecret')
    }
    const appraised = appraise(evidence, appraisalPolicy)
    if (!appraised.valid || appraised.claims === null) {
      throw new Error(`attestation appraisal failed: ${appraised.reasons.join('; ')}`)
    }
    const claims = appraised.claims
    return {
      sessionId: sessionId ?? claims.sessionId,
      sessionKey: deriveSessionKey(this.cfg.sessionRootSecret, claims),
      claims,
    }
  }

  /** Deny (return an outcome) if `session` is not bound to a verified attestation. */
  private checkAttestedSession(session: Session, now: number): AdmissionOutcome | null {
    let reason: string | null = null
    if (this.cfg.sessionRootSecret === undefined) {
      reason = 'requireAttestedSession is set but the node has no sessionRootSecret'
    } else {
      const expected = deriveSessionKey(this.cfg.sessionRootSecret, session.claims)
      if (!constantTimeEqual(session.sessionKey, expected)) {
        reason = 'session is not bound to a verified attestation (ATTEST-BIND-001)'
      }
    }
    // ATTEST-EXP-001 (Team Apex 2026-06-21): a correctly-BOUND session must also be FRESH.
    // Enforce the attestation's validity window (`claims.notAfter`) at admit time, fail-closed
    // on a non-finite admit clock / notAfter — otherwise an attested session is usable
    // indefinitely past its notAfter, defeating re-attestation / revocation. (The key still
    // matches; it is the EXPIRY, not the binding, that rejects here.)
    if (reason === null) {
      if (!Number.isSafeInteger(now) || !Number.isFinite(session.claims.notAfter)) {
        reason =
          'attested session freshness uncheckable: non-finite admit clock or notAfter (ATTEST-EXP-001)'
      } else if (now > session.claims.notAfter) {
        reason =
          'attested session expired: admit time is past the attestation notAfter (ATTEST-EXP-001)'
      }
    }
    if (reason === null) return null
    return {
      decision: {
        effect: 'deny',
        tier: 3,
        reasons: [reason],
        obligations: [],
        evaluatorVersion: evaluatorVersion(this.cfg.policy),
      },
      permit: null,
      receipt: null,
      inclusion: null,
      logRoot: null,
    }
  }
}
