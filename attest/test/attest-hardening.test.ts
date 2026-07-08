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

  it('F9: a FINITE-but-non-safe-integer signed notAfter (1e30 / fractional) is rejected, not immortal', () => {
    // Team Apex max sweep 2026-06-28: notAfter was guarded by Number.isFinite, so a SIGNED
    // notAfter of 1e30 (finite, not a safe integer) passed and `now > 1e30` was always false —
    // an attestation that never expires. It must now fail closed like Infinity does.
    for (const notAfter of [1e30, Number.MAX_VALUE, NOW + 0.4]) {
      const claims: AttestationClaims = {
        format: 'software-dev',
        sessionId: 's',
        sessionPublicKey: sessPub,
        nonce: NONCE,
        notAfter,
      }
      const ev: Evidence = {
        claims,
        format: 'software-dev',
        attesterPublicKey: A.publicKey,
        sig: signerFor(suite).sign(attMsg(claims), A.secretKey),
        suite,
      }
      expect(appraise(ev, basePolicy()).valid).toBe(false)
    }
  })

  it('F10: appraise can pin acceptedSuites / minCategory and rejects a weaker-suite (Cat-3) downgrade', () => {
    // A PS-1 (Cat-3) evidence signed by the SAME trusted ML-DSA-87 key A — signerFor collapses
    // every suite onto ML-DSA-87, so without a suite/category pin it is accepted where Cat-5 was
    // the security target (the silent downgrade F10 closes).
    const ps1 = SUITE_IDS.PS_1
    const claims: AttestationClaims = {
      format: 'software-dev',
      sessionId: 's',
      sessionPublicKey: sessPub,
      nonce: NONCE,
      notAfter: NOW + 300,
    }
    const ev: Evidence = {
      claims,
      format: 'software-dev',
      attesterPublicKey: A.publicKey,
      sig: signerFor(ps1).sign(encodeCanonical([ATTEST_CONTEXT, ps1, claims]), A.secretKey),
      suite: ps1,
    }
    // Otherwise accepted (no suite/category constraint) — this IS the downgrade.
    expect(appraise(ev, basePolicy()).valid).toBe(true)
    // A category floor pins it out (Cat-3 < 5):
    expect(appraise(ev, basePolicy({ minCategory: 5 })).valid).toBe(false)
    // A suite allowlist pins it out:
    expect(appraise(ev, basePolicy({ acceptedSuites: [SUITE_IDS.PS_5] })).valid).toBe(false)
    // Explicitly allowed / category met -> accepted (sanity, back-compatible):
    expect(appraise(ev, basePolicy({ acceptedSuites: [ps1] })).valid).toBe(true)
    expect(appraise(ev, basePolicy({ minCategory: 3 })).valid).toBe(true)
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

  it('ATTEST-NOFM-NOTAFTER-001: the n-of-m session inherits the MINIMUM notAfter across the quorum', () => {
    // Two trusted attesters corroborate the SAME session but with different expiries: A says NOW+300,
    // a far-future TDX quote says NOW+99999. The quorum session must expire at the CONSERVATIVE min
    // (NOW+300) — one attester's generous notAfter must not extend what the other vouched for.
    const farClaims: AttestationClaims = {
      format: 'tdx',
      sessionId: 's',
      sessionPublicKey: sessPub,
      nonce: NONCE,
      notAfter: NOW + 99999,
    }
    const tdxFar: Evidence = {
      claims: farClaims,
      format: 'tdx',
      attesterPublicKey: B.publicKey,
      sig: signerFor(suite).sign(attMsg(farClaims), B.secretKey),
      suite,
    }
    const r = appraiseNofM([evidenceA, tdxFar], basePolicy(), 2, verifiers)
    expect(r.valid).toBe(true)
    expect(r.claims!.notAfter).toBe(NOW + 300) // the MIN, not tdxFar's NOW+99999
  })

  it('ATTEST-NOFM-NOTAFTER-001: n-of-m attestations for DIFFERENT session ids do NOT form a quorum', () => {
    // sessionPublicKey agrees but sessionId differs → reject (parity with the sessionPublicKey pin).
    const otherId: AttestationClaims = {
      format: 'tdx',
      sessionId: 'DIFFERENT',
      sessionPublicKey: sessPub,
      nonce: NONCE,
      notAfter: NOW + 300,
    }
    const tdxOtherId: Evidence = {
      claims: otherId,
      format: 'tdx',
      attesterPublicKey: B.publicKey,
      sig: signerFor(suite).sign(attMsg(otherId), B.secretKey),
      suite,
    }
    expect(appraiseNofM([evidenceA, tdxOtherId], basePolicy(), 2, verifiers).valid).toBe(false)
  })

  it('ATTEST-SUITE-THROW: a bogus evidence.suite fails CLOSED, never throwing or aborting a quorum', () => {
    // evidence.suite is an attacker-controlled wire field; signerFor() throws on an unknown suite, so
    // appraise() must resolve it defensively (return invalid) rather than crash.
    const hostile: Evidence = { ...evidenceA, suite: 'PS-EVIL-9000' }
    expect(() => appraise(hostile, basePolicy())).not.toThrow()
    expect(appraise(hostile, basePolicy()).valid).toBe(false)
    // a single hostile-suite evidence must NOT abort an otherwise-valid n-of-m quorum (it is discarded)
    expect(() =>
      appraiseNofM([evidenceA, hostile, tdxEvidence(B)], basePolicy(), 2, verifiers),
    ).not.toThrow()
    expect(
      appraiseNofM([evidenceA, hostile, tdxEvidence(B)], basePolicy(), 2, verifiers).valid,
    ).toBe(true)
  })

  it('ATTEST-SHAPE-001: malformed evidence (null claims / null attester key) fails CLOSED, never throwing or aborting a quorum', () => {
    // evidence.claims (deref for .format) and evidence.attesterPublicKey (deref via constantTimeEqual)
    // are attacker-controlled wire fields read BEFORE the suite try/catch; a null must fail closed, not
    // TypeError-crash appraise() and abort an entire appraiseNofM quorum from one hostile item.
    const nullClaims = { ...evidenceA, claims: null } as unknown as Evidence
    const nullKey = { ...evidenceA, attesterPublicKey: null } as unknown as Evidence
    for (const bad of [nullClaims, nullKey]) {
      expect(() => appraise(bad, basePolicy())).not.toThrow()
      expect(appraise(bad, basePolicy()).valid).toBe(false)
    }
    // A single malformed evidence must NOT abort an otherwise-valid n-of-m quorum (it is discarded).
    expect(() =>
      appraiseNofM([evidenceA, nullClaims, tdxEvidence(B)], basePolicy(), 2, verifiers),
    ).not.toThrow()
    expect(
      appraiseNofM([evidenceA, nullClaims, tdxEvidence(B)], basePolicy(), 2, verifiers).valid,
    ).toBe(true)
  })

  it('MAX_EVIDENCES: an over-cap evidence array is rejected before per-item verification', () => {
    // Decode-side DoS cap: >256 evidences would otherwise force 256+ ML-DSA-87 verifies. Rejected up-front.
    const flood = Array.from({ length: 257 }, () => evidenceA)
    const r = appraiseNofM(flood, basePolicy(), 2, verifiers)
    expect(r.valid).toBe(false)
    expect(r.reasons.some((x) => x.includes('exceeds bound'))).toBe(true)
  })
})
