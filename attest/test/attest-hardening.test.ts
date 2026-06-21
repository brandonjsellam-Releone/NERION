// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, encodeCanonical } from '../../crypto/src/index.js'
import { SoftwareAttester, appraise, appraiseNofM, QuoteVerifierRegistry } from '../src/index.js'
import type { AppraisalPolicy, AttestationClaims, Evidence, QuoteVerifier } from '../src/index.js'

/**
 * Attestation hardening — Team Apex (2026-06-21), council-confirmed:
 *  - ATTEST-TIME-001: a non-finite `policy.now` (or signed `notAfter`) made the
 *    `now > notAfter` expiry test false and silently skipped it (fail-open) — same
 *    class as the fixed KERNEL-TIME-001. appraise() now fails closed.
 *  - ATTEST-NOFM-001: appraiseNofM counted distinct FORMATS only; one trusted
 *    attester could satisfy the quorum via relabeled formats. It now also requires
 *    n distinct ATTESTER keys (independent roots of trust).
 */
const suite = SUITE_IDS.PS_5
const A = signerFor(suite).keygen()
const B = signerFor(suite).keygen()
const session = signerFor(suite).keygen()
const NONCE = 'cafef00d'
const NOW = 1000
const sessPub = bytesToHex(session.publicKey)

// Mirror the (private) attestSigningMessage in software.ts: the evidence signature is
// suite-bound + domain-separated (ATTEST-SUITE-001), so hand-crafted evidence must sign
// over the same structure for appraise() to accept it.
const ATTEST_CONTEXT = 'polarseek/attest/evidence/v1'
const attMsg = (claims: AttestationClaims): Uint8Array =>
  encodeCanonical([ATTEST_CONTEXT, suite, claims])

const evidenceA = new SoftwareAttester(suite, A).produce('s', sessPub, NONCE, NOW + 300)

const basePolicy = (over: Partial<AppraisalPolicy> = {}): AppraisalPolicy => ({
  expectedNonce: NONCE,
  now: NOW,
  trustedAttesters: [A.publicKey, B.publicKey],
  acceptedFormats: ['software-dev', 'tdx'],
  expectedMeasurements: [],
  ...over,
})

// Hand-craft a signed 'tdx' evidence under an arbitrary attester key (a fake TEE quote).
function tdxEvidence(key: { secretKey: Uint8Array; publicKey: Uint8Array }): Evidence {
  const claims: AttestationClaims = {
    format: 'tdx',
    sessionId: 's',
    sessionPublicKey: sessPub,
    nonce: NONCE,
    notAfter: NOW + 300,
  }
  return {
    claims,
    format: 'tdx',
    attesterPublicKey: key.publicKey,
    sig: signerFor(suite).sign(attMsg(claims), key.secretKey),
    suite,
  }
}
const okTdxVerifier: QuoteVerifier = { format: 'tdx', verify: () => ({ ok: true, reasons: [] }) }
const verifiers = new QuoteVerifierRegistry().register(okTdxVerifier)

describe('attestation hardening (ATTEST-TIME-001 / ATTEST-NOFM-001)', () => {
  it('ATTEST-TIME-001: a non-finite policy.now fails closed (does not skip expiry)', () => {
    expect(appraise(evidenceA, basePolicy()).valid).toBe(true) // sanity: a good clock passes
    expect(appraise(evidenceA, basePolicy({ now: NaN })).valid).toBe(false)
    expect(appraise(evidenceA, basePolicy({ now: Infinity })).valid).toBe(false)
    // a genuinely expired attestation is still rejected
    expect(appraise(evidenceA, basePolicy({ now: NOW + 10_000 })).valid).toBe(false)
  })

  it('ATTEST-TIME-001: a non-finite signed notAfter is uncheckable -> rejected', () => {
    const claims: AttestationClaims = {
      format: 'software-dev',
      sessionId: 's',
      sessionPublicKey: sessPub,
      nonce: NONCE,
      notAfter: Infinity,
    }
    const ev: Evidence = {
      claims,
      format: 'software-dev',
      attesterPublicKey: A.publicKey,
      sig: signerFor(suite).sign(attMsg(claims), A.secretKey),
      suite,
    }
    expect(appraise(ev, basePolicy()).valid).toBe(false)
  })

  it('ATTEST-NOFM-001: distinct formats from ONE attester do NOT satisfy 2-of-M', () => {
    const swA = evidenceA // software-dev by A
    const tdxA = tdxEvidence(A) // tdx by A -> 2 formats, 1 attester
    expect(appraise(tdxA, basePolicy(), verifiers).valid).toBe(true) // each is individually valid
    expect(appraiseNofM([swA, tdxA], basePolicy(), 2, verifiers).valid).toBe(false)
  })

  it('ATTEST-NOFM-001: distinct formats AND distinct attesters satisfy 2-of-M', () => {
    const swA = evidenceA // software-dev by A
    const tdxB = tdxEvidence(B) // tdx by B -> 2 formats, 2 attesters
    expect(appraiseNofM([swA, tdxB], basePolicy(), 2, verifiers).valid).toBe(true)
  })

  it('ATTEST-NOFM-003: n-of-m attestations for DIFFERENT sessions do NOT form a quorum', () => {
    const sessionY = signerFor(suite).keygen()
    const claimsY: AttestationClaims = {
      format: 'tdx',
      sessionId: 's',
      sessionPublicKey: bytesToHex(sessionY.publicKey), // a DIFFERENT session than evidenceA
      nonce: NONCE,
      notAfter: NOW + 300,
    }
    const tdxBdiff: Evidence = {
      claims: claimsY,
      format: 'tdx',
      attesterPublicKey: B.publicKey,
      sig: signerFor(suite).sign(attMsg(claimsY), B.secretKey),
      suite,
    }
    // Each is individually valid, with 2 formats + 2 distinct attesters — but they corroborate
    // DIFFERENT sessions, so the n-of-m quorum must NOT certify either (cross-session forgery).
    expect(appraise(tdxBdiff, basePolicy(), verifiers).valid).toBe(true)
    expect(appraiseNofM([evidenceA, tdxBdiff], basePolicy(), 2, verifiers).valid).toBe(false)
    // Regression guard: the SAME session by 2 distinct attesters still forms a valid 2-of-2.
    expect(appraiseNofM([evidenceA, tdxEvidence(B)], basePolicy(), 2, verifiers).valid).toBe(true)
  })
})
