import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS, encodeCanonical } from '../../crypto/src/index.js'
import { appraise, QuoteVerifierRegistry } from '../src/index.js'
import type { AppraisalPolicy, Evidence, QuoteVerifier } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const attesterKey = signerFor(suite).keygen()
const NONCE = 'beadfeed'
const NOW = 2000
const MEASUREMENT = 'a'.repeat(64)

// Hand-build a TDX-format quote (in reality this comes from the TEE).
const claims = {
  format: 'tdx' as const,
  sessionId: 'sess-tee',
  sessionPublicKey: 'ff'.repeat(32),
  nonce: NONCE,
  notAfter: NOW + 300,
  measurement: MEASUREMENT,
}
const teeEvidence: Evidence = {
  claims,
  format: 'tdx',
  attesterPublicKey: attesterKey.publicKey,
  sig: signerFor(suite).sign(encodeCanonical(claims), attesterKey.secretKey),
  suite,
}

// A mock TDX quote verifier (the plug-point a real TDX adapter fills).
const tdxVerifier: QuoteVerifier = {
  format: 'tdx',
  verify(ev, expectedMeasurements) {
    const m = ev.claims.measurement
    return m !== undefined && expectedMeasurements.includes(m)
      ? { ok: true, reasons: [] }
      : { ok: false, reasons: ['enclave measurement not in the allowlist'] }
  },
}

const policy = (over: Partial<AppraisalPolicy> = {}): AppraisalPolicy => ({
  expectedNonce: NONCE,
  now: NOW,
  trustedAttesters: [attesterKey.publicKey],
  acceptedFormats: ['tdx'],
  expectedMeasurements: [MEASUREMENT],
  ...over,
})

describe('TEE quote-verifier adapter framework', () => {
  it('rejects a TEE format when no verifier is registered (CONNECT)', () => {
    const r = appraise(teeEvidence, policy())
    expect(r.valid).toBe(false)
    expect(r.reasons.join(' ')).toMatch(/not implemented|CONNECT/)
  })

  it('accepts a TEE quote once a verifier with a matching measurement is registered', () => {
    const registry = new QuoteVerifierRegistry().register(tdxVerifier)
    const r = appraise(teeEvidence, policy(), registry)
    expect(r.valid).toBe(true)
    expect(r.claims?.measurement).toBe(MEASUREMENT)
  })

  it('rejects a TEE quote whose measurement is not in the allowlist', () => {
    const registry = new QuoteVerifierRegistry().register(tdxVerifier)
    const r = appraise(teeEvidence, policy({ expectedMeasurements: ['b'.repeat(64)] }), registry)
    expect(r.valid).toBe(false)
    expect(r.reasons.join(' ')).toMatch(/measurement/)
  })

  it('still enforces nonce freshness on TEE quotes', () => {
    const registry = new QuoteVerifierRegistry().register(tdxVerifier)
    const r = appraise(teeEvidence, policy({ expectedNonce: 'stale' }), registry)
    expect(r.valid).toBe(false)
  })
})
