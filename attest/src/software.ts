/**
 * Software attester + the generic verifier (appraisal).
 *
 * SoftwareAttester signs a session statement with an attestation root key
 * (ML-DSA via the suite). `appraise` verifies the signature, trusted-attester
 * membership, nonce freshness, and expiry. Hardware TEE formats are rejected
 * with a CONNECT pointer until a real quote-verification adapter exists.
 */

import {
  encodeCanonical,
  signerFor,
  constantTimeEqual,
  type Bytes,
  type KeyPair,
} from '../../crypto/src/index.js'
import type { AppraisalPolicy, AppraisalResult, AttestationClaims, Evidence } from './types.js'

const HARDWARE_FORMATS = new Set(['tdx', 'sev-snp', 'cca', 'tpm'])

export class SoftwareAttester {
  constructor(
    private readonly suite: string,
    private readonly key: KeyPair,
  ) {}

  get publicKey(): Bytes {
    return this.key.publicKey
  }

  /** Produce signed evidence binding a session identity key + nonce. */
  produce(sessionId: string, sessionPublicKey: string, nonce: string, notAfter: number): Evidence {
    const claims: AttestationClaims = {
      format: 'software-dev',
      sessionId,
      sessionPublicKey,
      nonce,
      notAfter,
    }
    const sig = signerFor(this.suite).sign(encodeCanonical(claims), this.key.secretKey)
    return {
      claims,
      format: 'software-dev',
      attesterPublicKey: this.key.publicKey,
      sig,
      suite: this.suite,
    }
  }
}

/** Appraise a single piece of evidence against a policy. */
export function appraise(evidence: Evidence, policy: AppraisalPolicy): AppraisalResult {
  const reasons: string[] = []

  if (!policy.acceptedFormats.includes(evidence.format)) {
    reasons.push(`format "${evidence.format}" not accepted by policy`)
  }
  if (HARDWARE_FORMATS.has(evidence.format)) {
    reasons.push(
      `TEE quote verification for "${evidence.format}" is not implemented ` +
        `(CONNECT: ${evidence.format} attestation verification SDK)`,
    )
  }
  if (!policy.trustedAttesters.some((k) => constantTimeEqual(k, evidence.attesterPublicKey))) {
    reasons.push('attester key is not in the trusted set')
  }
  if (
    !signerFor(evidence.suite).verify(
      evidence.sig,
      encodeCanonical(evidence.claims),
      evidence.attesterPublicKey,
    )
  ) {
    reasons.push('evidence signature is invalid')
  }
  if (evidence.claims.nonce !== policy.expectedNonce) {
    reasons.push('nonce mismatch (stale or replayed attestation)')
  }
  if (policy.now > evidence.claims.notAfter) {
    reasons.push('attestation has expired')
  }

  return reasons.length === 0
    ? { valid: true, reasons, claims: evidence.claims }
    : { valid: false, reasons, claims: null }
}

/**
 * N-of-M heterogeneous appraisal for high tiers: valid iff at least `n`
 * evidences from DISTINCT formats appraise valid.
 */
export function appraiseNofM(
  evidences: readonly Evidence[],
  policy: AppraisalPolicy,
  n: number,
): AppraisalResult {
  const valid = evidences.map((e) => appraise(e, policy)).filter((r) => r.valid)
  const formats = new Set(valid.map((r) => r.claims!.format))
  if (formats.size >= n) {
    return { valid: true, reasons: [], claims: valid[0]!.claims }
  }
  return {
    valid: false,
    reasons: [`require ${n} heterogeneous valid attestations, got ${formats.size}`],
    claims: null,
  }
}
