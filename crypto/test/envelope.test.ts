import { describe, it, expect } from 'vitest'
import {
  signEnvelope,
  verifyEnvelope,
  openEnvelope,
  issuePermit,
  verifyPermit,
  readPermit,
} from '../src/envelope.js'
import { signerFor, SUITE_IDS } from '../src/suites.js'
import { randomBytes } from '../src/symmetric.js'

describe('signed envelope (nearline plane)', () => {
  const { publicKey, secretKey } = signerFor(SUITE_IDS.PS_5).keygen()
  const payload = { intent: 'deploy', target: 'prod', tier: 2 }

  it('signs and verifies, carrying its SuiteID, and opens to the payload', () => {
    const env = signEnvelope(payload, SUITE_IDS.PS_5, secretKey, 'receipt')
    expect(env.suite).toBe(SUITE_IDS.PS_5)
    expect(verifyEnvelope(env, publicKey)).toBe(true)
    expect(openEnvelope(env)).toEqual(payload)
  })

  it('rejects a tampered payload', () => {
    const env = signEnvelope(payload, SUITE_IDS.PS_5, secretKey, 'receipt')
    const tampered = { ...env, payload: Uint8Array.from(env.payload) }
    tampered.payload[2] = (tampered.payload[2] as number) ^ 0xff
    expect(verifyEnvelope(tampered, publicKey)).toBe(false)
  })

  it('rejects a context change (domain separation)', () => {
    const env = signEnvelope(payload, SUITE_IDS.PS_5, secretKey, 'receipt')
    expect(verifyEnvelope({ ...env, context: 'capability' }, publicKey)).toBe(false)
  })

  it('rejects a SuiteID downgrade in the envelope', () => {
    const env = signEnvelope(payload, SUITE_IDS.PS_5, secretKey, 'receipt')
    // Both PS-5 and PS-1 use ML-DSA-87, but the suite is bound into the
    // signed transcript, so swapping it invalidates the signature.
    expect(verifyEnvelope({ ...env, suite: SUITE_IDS.PS_1 }, publicKey)).toBe(false)
  })
})

describe('PermitToken (hot plane, HMAC-SHA-384)', () => {
  const sessionKey = randomBytes(48)
  const claims = { tier: 1, ceiling: 100, exp: 1750000000, nonce: 'abc' }

  it('issues and verifies with the session key, and reads back claims', () => {
    const token = issuePermit(claims, SUITE_IDS.PS_5, sessionKey)
    expect(token.mac.length).toBe(48)
    expect(verifyPermit(token, sessionKey)).toBe(true)
    expect(readPermit(token)).toEqual(claims)
  })

  it('rejects the wrong session key', () => {
    const token = issuePermit(claims, SUITE_IDS.PS_5, sessionKey)
    expect(verifyPermit(token, randomBytes(48))).toBe(false)
  })

  it('rejects a tampered body', () => {
    const token = issuePermit(claims, SUITE_IDS.PS_5, sessionKey)
    const bad = { ...token, body: Uint8Array.from(token.body) }
    bad.body[1] = (bad.body[1] as number) ^ 0xff
    expect(verifyPermit(bad, sessionKey)).toBe(false)
  })

  it('rejects a SuiteID swap', () => {
    const token = issuePermit(claims, SUITE_IDS.PS_5, sessionKey)
    expect(verifyPermit({ ...token, suite: SUITE_IDS.PS_1 }, sessionKey)).toBe(false)
  })
})
