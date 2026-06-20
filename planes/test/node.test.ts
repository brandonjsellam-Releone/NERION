// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, randomBytes } from '../../crypto/src/index.js'
import { issueRoot, type ActionIntent } from '../../capabilities/src/index.js'
import { DEFAULT_POLICY } from '../../kernel/src/index.js'
import { TransparencyLog } from '../../translog/src/index.js'
import { verifyReceiptInclusion } from '../../receipts/src/index.js'
import { SoftwareAttester, appraise } from '../../attest/src/index.js'
import { PolarSeekNode, verifyPermitForAction, type Session } from '../src/index.js'

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

// Establish an attested session for the agent.
const evidence = attester.produce('sess-9', agentHex, NONCE, NOW + 300)
const appraised = appraise(evidence, {
  expectedNonce: NONCE,
  now: NOW,
  trustedAttesters: [attesterKey.publicKey],
  acceptedFormats: ['software-dev'],
})
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

// A read-scoped capability: no counterparty restriction (reads have no counterparty).
const capRead = issueRoot(
  {
    subject: agentHex,
    actions: ['data.read'],
    perActionCeiling: null,
    aggregateCap: null,
    counterparties: null,
    maxTier: 0,
    notBefore: 0,
    notAfter: NOW + 86_400,
    delegable: false,
  },
  suite,
  authority,
)

function makeNode(): PolarSeekNode {
  return new PolarSeekNode({
    suite,
    policy: DEFAULT_POLICY,
    trustedRoots: [authority.publicKey],
    issuer,
    log: new TransparencyLog(),
    jurisdiction: 'US',
    permitTtlSeconds: 30,
  })
}

const pay = (amount: number): ActionIntent => ({
  type: 'payment.transfer',
  resource: 'acct://treasury',
  counterparty: 'vendor-acme',
  amount,
})

describe('attested session', () => {
  it('the agent session is validly attested', () => {
    expect(appraised.valid).toBe(true)
  })
})

describe('PolarSeekNode admission', () => {
  it('admits a T2 payment, issues a bound permit, and anchors a verifiable receipt', () => {
    const node = makeNode()
    const out = node.admit({
      intent: pay(500),
      capabilities: [cap],
      session,
      audience: 'acct://treasury',
      now: NOW,
      observedAggregate: 0,
    })

    expect(out.decision.effect).toBe('allow')
    expect(out.decision.tier).toBe(2)
    expect(out.permit).not.toBeNull()
    expect(out.receipt).not.toBeNull()
    expect(out.inclusion).not.toBeNull()

    // External verification of the receipt with no operator trust.
    const verdict = verifyReceiptInclusion(
      out.receipt!,
      out.inclusion!,
      out.logRoot!,
      issuer.publicKey,
    )
    expect(verdict.ok).toBe(true)
  })

  it('the permit verifies for the exact bound action only (replay defense)', () => {
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

    // Correct action + audience + time: OK.
    expect(
      verifyPermitForAction(permit, session.sessionKey, {
        audience: 'acct://treasury',
        intent: pay(500),
        now: NOW + 5,
      }).ok,
    ).toBe(true)

    // Different action (amount) -> not bound.
    expect(
      verifyPermitForAction(permit, session.sessionKey, {
        audience: 'acct://treasury',
        intent: pay(600),
        now: NOW + 5,
      }).ok,
    ).toBe(false)

    // Different resource (audience) -> rejected.
    expect(
      verifyPermitForAction(permit, session.sessionKey, {
        audience: 'acct://other',
        intent: pay(500),
        now: NOW + 5,
      }).ok,
    ).toBe(false)

    // Expired -> rejected.
    expect(
      verifyPermitForAction(permit, session.sessionKey, {
        audience: 'acct://treasury',
        intent: pay(500),
        now: NOW + 999,
      }).ok,
    ).toBe(false)

    // Wrong session key -> rejected.
    expect(
      verifyPermitForAction(permit, randomBytes(48), {
        audience: 'acct://treasury',
        intent: pay(500),
        now: NOW + 5,
      }).ok,
    ).toBe(false)
  })

  it('denies an over-ceiling payment and issues no permit', () => {
    const node = makeNode()
    const out = node.admit({
      intent: pay(5000),
      capabilities: [cap],
      session,
      audience: 'acct://treasury',
      now: NOW,
      observedAggregate: 0,
    })
    expect(out.decision.effect).toBe('deny')
    expect(out.permit).toBeNull()
    expect(out.receipt).toBeNull()
  })

  it('admits a T0 read with a permit but no nearline receipt', () => {
    const node = makeNode()
    const out = node.admit({
      intent: { type: 'data.read', resource: 'doc://x' },
      capabilities: [cap, capRead],
      session,
      audience: 'doc://x',
      now: NOW,
      observedAggregate: 0,
    })
    expect(out.decision.effect).toBe('allow')
    expect(out.decision.tier).toBe(0)
    expect(out.permit).not.toBeNull()
    expect(out.receipt).toBeNull()
  })
})
