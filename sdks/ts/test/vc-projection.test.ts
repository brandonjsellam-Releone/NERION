// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  permitToVerifiableCredential,
  receiptToVerifiablePresentation,
  permitToEidasAttestation,
} from '../src/vc-projection.js'

const permit = {
  audience: 'res-acme',
  actionHash: 'abcd1234',
  tier: 2,
  exp: 1893456000,
  effect: 'allow',
  evaluator: 'kernel-v1',
}
const intent = {
  type: 'payment.transfer',
  resource: 'acct-123',
  counterparty: 'vendor-x',
  amount: 5000,
}

describe('W3C-VC projection (B12 Phase-A, presentational only)', () => {
  it('projects a permit to a W3C-VC 2.0 credential with the v2 context + native proof reference', () => {
    const vc = permitToVerifiableCredential(permit, intent, {
      issuerDid: 'did:nerion:mainnet:zABC',
      validFromIso: '2026-06-26T00:00:00Z',
    })
    expect(vc['@context'][0]).toBe('https://www.w3.org/ns/credentials/v2')
    expect(vc.type).toContain('NerionPermitCredential')
    expect(vc.credentialSubject.action).toBe('payment.transfer')
    expect(vc.credentialSubject.amount).toBe(5000)
    // The proof REFERENCES the native ML-DSA-87 signature; it does not re-sign.
    expect(vc.proof.type).toBe('NerionMLDSA87Signature2026')
  })

  it('omits optional fields when absent (no undefined leakage into the document)', () => {
    const vc = permitToVerifiableCredential(
      permit,
      { type: 'data.read', resource: 'r' },
      { issuerDid: 'did:nerion:x', validFromIso: '2026-06-26T00:00:00Z' },
    )
    expect('counterparty' in vc.credentialSubject).toBe(false)
    expect('amount' in vc.credentialSubject).toBe(false)
    expect('validUntil' in vc).toBe(false)
  })

  it('carries proofValue and validUntil through when supplied', () => {
    const vc = permitToVerifiableCredential(permit, intent, {
      issuerDid: 'did:nerion:x',
      validFromIso: '2026-06-26T00:00:00Z',
      validUntilIso: '2026-07-01T00:00:00Z',
      proofValueB64Url: 'zSIGB64URL',
    })
    expect(vc.validUntil).toBe('2026-07-01T00:00:00Z')
    expect(vc.proof.proofValue).toBe('zSIGB64URL')
  })

  it('projects a receipt to a verifiable presentation', () => {
    const vp = receiptToVerifiablePresentation(
      {
        action: 'payment.transfer',
        tier: 2,
        effect: 'allow',
        evaluatorVersion: 'v1',
        merkleRoot: 'root',
      },
      'did:nerion:holder',
    )
    expect(vp.type).toContain('NerionActionReceiptPresentation')
    expect(vp.nerionReceipt.merkleRoot).toBe('root')
  })

  it('projects a permit to an eIDAS attestation tagged with the FIPS algorithm', () => {
    const att = permitToEidasAttestation(permit, intent, {
      organizationIdentifier: 'TRELYAN',
      country: 'US',
    })
    expect((att.attributes as Record<string, unknown>).cryptographicAlgorithm).toBe(
      'ML-DSA-87 (FIPS 204)',
    )
  })
})
