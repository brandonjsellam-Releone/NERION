// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, randomBytes, decodeCbor } from '../../crypto/src/index.js'
import { issueRoot, type ActionIntent } from '../../capabilities/src/index.js'
import { DEFAULT_POLICY } from '../../kernel/src/index.js'
import { TransparencyLog } from '../../translog/src/index.js'
import { SoftwareAttester, type AppraisalPolicy } from '../../attest/src/index.js'
import { PolarSeekNode } from '../src/index.js'

/**
 * ATTEST-EXP-001 (Team Apex post-fix verification, 2026-06-21). With
 * `requireAttestedSession`, the session key proves an appraisal happened ONCE (at
 * `establishSession`). But admission must ALSO enforce the attestation's validity
 * window (`claims.notAfter`) at admit time — otherwise an attested session is usable
 * indefinitely past its `notAfter`, defeating re-attestation / revocation. The key
 * binding (ATTEST-BIND-001) is sound; this covers the freshness gap, fail-closed.
 */
const suite = SUITE_IDS.PS_5
const s = signerFor(suite)
const authority = s.keygen()
const agent = s.keygen()
const issuer = s.keygen()
const attesterKey = s.keygen()
const attester = new SoftwareAttester(suite, attesterKey)
const rootSecret = randomBytes(32)

const NOW = 1_750_000_000
const NOT_AFTER = NOW + 300
const NONCE = 'feedface'
const agentHex = bytesToHex(agent.publicKey)

const evidence = attester.produce('sess-exp', agentHex, NONCE, NOT_AFTER)
const attPolicy: AppraisalPolicy = {
  expectedNonce: NONCE,
  now: NOW,
  trustedAttesters: [attesterKey.publicKey],
  acceptedFormats: ['software-dev'],
}

const cap = issueRoot(
  {
    subject: agentHex,
    actions: ['payment.transfer'],
    perActionCeiling: 1000,
    aggregateCap: null,
    counterparties: ['vendor-acme'],
    maxTier: 2,
    notBefore: 0,
    notAfter: NOW + 86_400,
    delegable: false,
  },
  suite,
  authority,
)

const pay = (amount: number): ActionIntent => ({
  type: 'payment.transfer',
  resource: 'acct://treasury',
  counterparty: 'vendor-acme',
  amount,
})

function attestedNode(): PolarSeekNode {
  return new PolarSeekNode({
    suite,
    policy: DEFAULT_POLICY,
    trustedRoots: [authority.publicKey],
    issuer,
    log: new TransparencyLog(),
    jurisdiction: 'US',
    permitTtlSeconds: 30,
    sessionRootSecret: rootSecret,
    requireAttestedSession: true,
  })
}

describe('ATTEST-EXP-001 — attested session expires at its attestation notAfter', () => {
  it('admits within the attestation window, denies once notAfter has passed', () => {
    const node = attestedNode()
    const session = node.establishSession(evidence, attPolicy)
    const reqAt = (now: number) => ({
      intent: pay(500),
      capabilities: [cap],
      session,
      audience: 'acct://treasury',
      now,
      observedAggregate: 0,
    })

    // Inside the window (now <= notAfter): admitted.
    expect(node.admit(reqAt(NOW)).decision.effect).toBe('allow')
    expect(node.admit(reqAt(NOT_AFTER)).decision.effect).toBe('allow') // boundary: now == notAfter

    // Past the window: DENIED with the freshness reason (the key still matches —
    // it is the expiry, not the binding, that rejects).
    const expired = node.admit(reqAt(NOT_AFTER + 1))
    expect(expired.decision.effect).toBe('deny')
    expect(expired.decision.reasons.join(' ')).toMatch(/ATTEST-EXP-001|expired/)
    expect(node.admit(reqAt(NOW + 10_000)).decision.effect).toBe('deny')
  })

  it('fails closed on a non-finite admit clock', () => {
    const node = attestedNode()
    const session = node.establishSession(evidence, attPolicy)
    const out = node.admit({
      intent: pay(500),
      capabilities: [cap],
      session,
      audience: 'acct://treasury',
      now: NaN,
      observedAggregate: 0,
    })
    expect(out.decision.effect).toBe('deny')
  })

  it('PERMIT-EXP-CLAMP: a permit expiry never outlives the attestation notAfter', () => {
    const node = attestedNode() // permitTtlSeconds: 30; attestation NOT_AFTER = NOW + 300
    const session = node.establishSession(evidence, attPolicy)
    const expOf = (now: number): number => {
      const out = node.admit({
        intent: pay(500),
        capabilities: [cap],
        session,
        audience: 'acct://treasury',
        now,
        observedAggregate: 0,
      })
      expect(out.decision.effect).toBe('allow')
      return (decodeCbor(out.permit!.body) as { exp: number }).exp
    }
    // Early: now + ttl (NOW+30) is well within notAfter → plain TTL, not clamped.
    expect(expOf(NOW)).toBe(NOW + 30)
    // Late: now + ttl (NOT_AFTER-10 + 30 = NOT_AFTER+20) would outlive the attestation → clamped DOWN
    // to notAfter, so a permit can never be honored past the freshness window ATTEST-EXP-001 enforces.
    expect(expOf(NOT_AFTER - 10)).toBe(NOT_AFTER)
  })
})
