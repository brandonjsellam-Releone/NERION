// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import {
  signEnvelope,
  verifyEnvelope,
  openEnvelope,
  issuePermit,
  verifyPermit,
  readPermit,
  deriveAudiencePermitKey,
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

describe('per-audience permit-key derivation (HKDF-SHA-384, ADR-0015)', () => {
  const sessionKey = randomBytes(48)
  const claims = { tier: 1, audience: 'acct://A', exp: 1750000000, nonce: 'abc' }

  it('derives a 48-byte key, deterministically, distinct per audience', () => {
    const a1 = deriveAudiencePermitKey(sessionKey, 'acct://A')
    const a2 = deriveAudiencePermitKey(sessionKey, 'acct://A')
    const b = deriveAudiencePermitKey(sessionKey, 'acct://B')
    expect(a1.length).toBe(48)
    // Deterministic for the same (session, audience).
    expect(bytesToHex(a1)).toBe(bytesToHex(a2))
    // Independent across audiences, and never equal to the raw session secret.
    expect(bytesToHex(a1)).not.toBe(bytesToHex(b))
    expect(bytesToHex(a1)).not.toBe(bytesToHex(sessionKey))
  })

  it('a permit MAC-bound to one audience key does not verify under another', () => {
    const keyA = deriveAudiencePermitKey(sessionKey, 'acct://A')
    const keyB = deriveAudiencePermitKey(sessionKey, 'acct://B')
    const token = issuePermit(claims, SUITE_IDS.PS_5, keyA)
    expect(verifyPermit(token, keyA)).toBe(true)
    expect(verifyPermit(token, keyB)).toBe(false)
  })

  it('PERMIT-001: a holder of only one audience key cannot forge for another', () => {
    const keyA = deriveAudiencePermitKey(sessionKey, 'acct://A')
    const keyB = deriveAudiencePermitKey(sessionKey, 'acct://B')
    // Attacker holds keyB only; re-MACs claims that name audience A.
    const forged = issuePermit({ ...claims, audience: 'acct://A' }, SUITE_IDS.PS_5, keyB)
    // The audience-A resource (keyA) rejects it: the MAC was not made under keyA.
    expect(verifyPermit(forged, keyA)).toBe(false)
  })
})
