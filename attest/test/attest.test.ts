// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { SoftwareAttester, appraise, appraiseNofM } from '../src/index.js'
import type { AppraisalPolicy, Evidence } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const attesterKey = signerFor(suite).keygen()
const sessionKey = signerFor(suite).keygen()
const attester = new SoftwareAttester(suite, attesterKey)

const NONCE = 'cafef00d'
const NOW = 1000
const sessionPubHex = bytesToHex(sessionKey.publicKey)
const evidence = attester.produce('sess-1', sessionPubHex, NONCE, NOW + 300)

const policy = (over: Partial<AppraisalPolicy> = {}): AppraisalPolicy => ({
  expectedNonce: NONCE,
  now: NOW,
  trustedAttesters: [attesterKey.publicKey],
  acceptedFormats: ['software-dev'],
  ...over,
})

describe('attestation appraisal', () => {
  it('accepts fresh, signed, trusted evidence', () => {
    const r = appraise(evidence, policy())
    expect(r.valid).toBe(true)
    expect(r.claims?.sessionPublicKey).toBe(sessionPubHex)
  })

  it('rejects a stale/replayed nonce', () => {
    expect(appraise(evidence, policy({ expectedNonce: 'deadbeef' })).valid).toBe(false)
  })

  it('rejects expired attestation', () => {
    expect(appraise(evidence, policy({ now: NOW + 10_000 })).valid).toBe(false)
  })

  it('rejects an untrusted attester', () => {
    const other = signerFor(suite).keygen()
    expect(appraise(evidence, policy({ trustedAttesters: [other.publicKey] })).valid).toBe(false)
  })

  it('rejects a tampered signature', () => {
    const badSig = Uint8Array.from(evidence.sig)
    badSig[0] = (badSig[0] as number) ^ 0xff
    expect(appraise({ ...evidence, sig: badSig }, policy()).valid).toBe(false)
  })

  it('rejects hardware TEE formats until an adapter is wired (CONNECT)', () => {
    const teeClaims = { ...evidence.claims, format: 'tdx' as const }
    const sig = signerFor(suite).sign(new TextEncoder().encode('x'), attesterKey.secretKey)
    const tee: Evidence = { ...evidence, format: 'tdx', claims: teeClaims, sig }
    const r = appraise(tee, policy({ acceptedFormats: ['software-dev', 'tdx'] }))
    expect(r.valid).toBe(false)
    expect(r.reasons.join(' ')).toMatch(/not implemented|CONNECT/)
  })

  it('N-of-M requires that many distinct valid formats', () => {
    expect(appraiseNofM([evidence], policy(), 1).valid).toBe(true)
    expect(appraiseNofM([evidence], policy(), 2).valid).toBe(false)
  })
})
