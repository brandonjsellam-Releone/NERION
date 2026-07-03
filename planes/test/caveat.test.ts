// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Permit caveats (Team Apex R&D 2026-06-28) — offline, macaroon-style least-privilege attenuation.
 * Proves the value-adding case (offline expiry tightening), the macaroon security properties
 * (strip-resistance, chain integrity, conjunctive stacking, DoS bound), and that caveats only ever
 * narrow. See planes/src/caveat.ts + docs/PERMIT-CAVEATS.md.
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, randomBytes, type PermitToken } from '../../crypto/src/index.js'
import { issueRoot, type ActionIntent } from '../../capabilities/src/index.js'
import { DEFAULT_POLICY } from '../../kernel/src/index.js'
import { TransparencyLog } from '../../translog/src/index.js'
import { SoftwareAttester } from '../../attest/src/index.js'
import {
  PolarSeekNode,
  deriveAudiencePermitKey,
  verifyPermitForAction,
  attenuate,
  verifyAttenuatedPermit,
  type Session,
  type PermitCheck,
  type AttenuatedPermit,
} from '../src/index.js'

const suite = SUITE_IDS.PS_5
const s = signerFor(suite)
const authority = s.keygen()
const agent = s.keygen()
const issuer = s.keygen()
const attesterKey = s.keygen()
const attester = new SoftwareAttester(suite, attesterKey)

const NOW = 1_750_000_000
const agentHex = bytesToHex(agent.publicKey)
const NONCE = 'feedface'

const evidence = attester.produce('sess-9', agentHex, NONCE, NOW + 300)
const session: Session = {
  sessionId: 'sess-9',
  sessionKey: randomBytes(48),
  claims: evidence.claims,
}

const cap = issueRoot(
  {
    subject: agentHex,
    actions: ['payment.transfer', 'data.read'],
    perActionCeiling: 1000,
    aggregateCap: 5000,
    counterparties: ['vendor-acme'],
    maxTier: 2,
    notBefore: 0,
    notAfter: NOW + 86_400,
    delegable: false,
  },
  suite,
  authority,
)

const makeNode = (): PolarSeekNode =>
  new PolarSeekNode({
    suite,
    policy: DEFAULT_POLICY,
    trustedRoots: [authority.publicKey],
    issuer,
    log: new TransparencyLog(),
    jurisdiction: 'US',
    permitTtlSeconds: 30,
  })

const pay = (amount: number): ActionIntent => ({
  type: 'payment.transfer',
  resource: 'acct://treasury',
  counterparty: 'vendor-acme',
  amount,
})

describe('permit caveats — offline macaroon-style attenuation', () => {
  const node = makeNode()
  const out = node.admit({
    intent: pay(500),
    capabilities: [cap],
    session,
    audience: 'acct://treasury',
    now: NOW,
    observedAggregate: 0,
  })
  const permit = out.permit!
  const key = deriveAudiencePermitKey(session.sessionKey, 'acct://treasury')
  const check = (now: number, intent: ActionIntent = pay(500)): PermitCheck => ({
    audience: 'acct://treasury',
    intent,
    now,
  })

  it('sanity: the base permit is allow and valid up to its exp (~NOW+30)', () => {
    expect(out.decision.effect).toBe('allow')
    expect(verifyPermitForAction(permit, key, check(NOW + 3)).ok).toBe(true)
    expect(verifyPermitForAction(permit, key, check(NOW + 10)).ok).toBe(true)
  })

  it('AAC cycle-4 (F5 parity): an oversized attenuated-permit body is rejected BEFORE the HMAC', () => {
    // The F5 size cap only lived in the non-attenuated verifyPermitForAction (which runs AFTER
    // permitMac here). Without a pre-check, an attacker forces a full canonical-encode + HMAC over an
    // unauthenticated multi-MB body. The cap must reject an oversized body up-front.
    const huge: AttenuatedPermit = {
      suite,
      body: new Uint8Array(9000), // > MAX_PERMIT_BODY_BYTES (8192)
      caveats: [],
      mac: new Uint8Array(48),
    }
    expect(verifyAttenuatedPermit(huge, key, check(NOW)).ok).toBe(false)
  })

  it('AAC cycle-4: a non-array caveats field fails closed (verdict), not a thrown TypeError', () => {
    const bad = {
      suite,
      body: new Uint8Array(16),
      caveats: undefined,
      mac: new Uint8Array(48),
    } as unknown as AttenuatedPermit
    expect(() => verifyAttenuatedPermit(bad, key, check(NOW))).not.toThrow()
    expect(verifyAttenuatedPermit(bad, key, check(NOW)).ok).toBe(false)
  })

  it('expiresAtMost: a holder tightens the lifetime OFFLINE; the resource enforces the shorter window', () => {
    const ap = attenuate(permit, { kind: 'expiresAtMost', value: NOW + 5 })
    expect(verifyAttenuatedPermit(ap, key, check(NOW + 3)).ok).toBe(true) // within base AND caveat
    expect(verifyAttenuatedPermit(ap, key, check(NOW + 10)).ok).toBe(false) // past the caveat
    // The un-attenuated base permit is still valid at NOW+10 — so the caveat (added with NO audience
    // key) is what rejected, not the base.
    expect(verifyPermitForAction(permit, key, check(NOW + 10)).ok).toBe(true)
  })

  it('strip-resistance: a recipient cannot fall back to the base permit (no M0 is forwarded)', () => {
    const ap = attenuate(permit, { kind: 'expiresAtMost', value: NOW + 5 })
    // The recipient holds only {suite, body, caveats, mac=M1}. A bare PermitToken built from it
    // (mac=M1) fails verifyPermit because M1 != M0 = HMAC(audienceKey, toBeMaced).
    const stripped: PermitToken = { suite: ap.suite, body: ap.body, mac: ap.mac }
    expect(verifyPermitForAction(stripped, key, check(NOW + 3)).ok).toBe(false)
    // Dropping the caveat (keeping M1) breaks the chain: chainMac(M0, []) = M0 != M1.
    const dropped: AttenuatedPermit = { ...ap, caveats: [] }
    expect(verifyAttenuatedPermit(dropped, key, check(NOW + 3)).ok).toBe(false)
  })

  it('a tampered caveat value breaks the MAC chain', () => {
    const ap = attenuate(permit, { kind: 'expiresAtMost', value: NOW + 5 })
    const tampered: AttenuatedPermit = {
      ...ap,
      caveats: [{ kind: 'expiresAtMost', value: NOW + 99_999 }],
    }
    expect(verifyAttenuatedPermit(tampered, key, check(NOW + 100)).ok).toBe(false)
  })

  it('caveats stack conjunctively — the tightest expiry wins', () => {
    const ap = attenuate(attenuate(permit, { kind: 'expiresAtMost', value: NOW + 20 }), {
      kind: 'expiresAtMost',
      value: NOW + 5,
    })
    expect(verifyAttenuatedPermit(ap, key, check(NOW + 3)).ok).toBe(true)
    expect(verifyAttenuatedPermit(ap, key, check(NOW + 10)).ok).toBe(false) // past the NOW+5 caveat
  })

  it('a wrong audience key is rejected (M0 is recomputed from the key, never transmitted)', () => {
    const ap = attenuate(permit, { kind: 'expiresAtMost', value: NOW + 5 })
    const wrongKey = deriveAudiencePermitKey(session.sessionKey, 'acct://other')
    expect(verifyAttenuatedPermit(ap, wrongKey, check(NOW + 3)).ok).toBe(false)
  })

  it('rejects an over-long caveat chain fail-closed (DoS bound)', () => {
    let ap = attenuate(permit, { kind: 'expiresAtMost', value: NOW + 5 })
    for (let i = 0; i < 20; i++) ap = attenuate(ap, { kind: 'expiresAtMost', value: NOW + 5 })
    expect(verifyAttenuatedPermit(ap, key, check(NOW + 3)).ok).toBe(false) // > MAX_CAVEATS (16)
  })

  it('amountAtMost enforces mechanically (sound; redundant with the bound actionHash)', () => {
    expect(
      verifyAttenuatedPermit(
        attenuate(permit, { kind: 'amountAtMost', value: 100 }),
        key,
        check(NOW + 3),
      ).ok,
    ).toBe(false) // base is for amount 500; caveat forbids > 100
    expect(
      verifyAttenuatedPermit(
        attenuate(permit, { kind: 'amountAtMost', value: 1000 }),
        key,
        check(NOW + 3),
      ).ok,
    ).toBe(true)
  })
})
