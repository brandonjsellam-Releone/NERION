// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, randomBytes, issuePermit } from '../../crypto/src/index.js'
import { issueRoot, type ActionIntent } from '../../capabilities/src/index.js'
import { DEFAULT_POLICY } from '../../kernel/src/index.js'
import { TransparencyLog } from '../../translog/src/index.js'
import {
  verifyReceiptInclusion,
  receiptLeaf,
  verifyIntentDisclosure,
} from '../../receipts/src/index.js'
import { SoftwareAttester, appraise, type AppraisalPolicy } from '../../attest/src/index.js'
import {
  PolarSeekNode,
  verifyPermitForAction,
  deriveAudiencePermitKey,
  actionHash,
  type Session,
  type PermitClaims,
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

  it('carries a hiding intent salt on the receipt, disclosable by an authorized verifier (RCPT-001)', () => {
    const node = makeNode()
    const intent = pay(500)
    const out = node.admit({
      intent,
      capabilities: [cap],
      session,
      audience: 'acct://treasury',
      now: NOW,
      observedAggregate: 0,
    })
    expect(out.receipt).not.toBeNull()
    // The node mints a high-entropy salt; it rides on the receipt, NOT in the log leaf.
    expect(out.receipt!.intentSalt.length).toBeGreaterThanOrEqual(32)
    expect(bytesToHex(receiptLeaf(out.receipt!))).not.toContain(bytesToHex(out.receipt!.intentSalt))
    // An authorized verifier with the salt discloses the intent; a tampered amount is rejected.
    expect(verifyIntentDisclosure(out.receipt!, intent)).toBe(true)
    expect(verifyIntentDisclosure(out.receipt!, pay(501))).toBe(false)
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
    // The treasury resource is provisioned with ONLY its audience-scoped key.
    const treasuryKey = deriveAudiencePermitKey(session.sessionKey, 'acct://treasury')

    // Correct action + audience + time: OK.
    expect(
      verifyPermitForAction(permit, treasuryKey, {
        audience: 'acct://treasury',
        intent: pay(500),
        now: NOW + 5,
      }).ok,
    ).toBe(true)

    // Different action (amount) -> not bound.
    expect(
      verifyPermitForAction(permit, treasuryKey, {
        audience: 'acct://treasury',
        intent: pay(600),
        now: NOW + 5,
      }).ok,
    ).toBe(false)

    // Different resource (audience): its key cannot verify the treasury permit
    // (the MAC, not just the claim, binds the audience now).
    const otherKey = deriveAudiencePermitKey(session.sessionKey, 'acct://other')
    expect(
      verifyPermitForAction(permit, otherKey, {
        audience: 'acct://other',
        intent: pay(500),
        now: NOW + 5,
      }).ok,
    ).toBe(false)

    // Expired -> rejected.
    expect(
      verifyPermitForAction(permit, treasuryKey, {
        audience: 'acct://treasury',
        intent: pay(500),
        now: NOW + 999,
      }).ok,
    ).toBe(false)

    // Wrong key -> rejected.
    expect(
      verifyPermitForAction(permit, randomBytes(48), {
        audience: 'acct://treasury',
        intent: pay(500),
        now: NOW + 5,
      }).ok,
    ).toBe(false)
  })

  it('the permit binds the kernel effect (expectedEffect is enforced)', () => {
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
    const treasuryKey = deriveAudiencePermitKey(session.sessionKey, 'acct://treasury')
    // Same effect the kernel decided: OK.
    expect(
      verifyPermitForAction(permit, treasuryKey, {
        audience: 'acct://treasury',
        intent: pay(500),
        now: NOW + 5,
        expectedEffect: 'allow',
      }).ok,
    ).toBe(true)
    // A resource expecting a different effect rejects (no transform<->allow confusion).
    expect(
      verifyPermitForAction(permit, treasuryKey, {
        audience: 'acct://treasury',
        intent: pay(500),
        now: NOW + 5,
        expectedEffect: 'transform',
      }).ok,
    ).toBe(false)
  })

  it('F4: a transform permit is rejected by default (no silent transform->allow), accepted on opt-in', () => {
    const node = new PolarSeekNode({
      suite,
      policy: { ...DEFAULT_POLICY, transformActions: ['payment.transfer'] },
      trustedRoots: [authority.publicKey],
      issuer,
      log: new TransparencyLog(),
      jurisdiction: 'US',
      permitTtlSeconds: 30,
    })
    const out = node.admit({
      intent: pay(500),
      capabilities: [cap],
      session,
      audience: 'acct://treasury',
      now: NOW,
      observedAggregate: 0,
    })
    expect(out.decision.effect).toBe('transform')
    const treasuryKey = deriveAudiencePermitKey(session.sessionKey, 'acct://treasury')
    // No expectedEffect now defaults to requiring 'allow' — a transform permit is rejected.
    expect(
      verifyPermitForAction(out.permit!, treasuryKey, {
        audience: 'acct://treasury',
        intent: pay(500),
        now: NOW + 5,
      }).ok,
    ).toBe(false)
    // A resource that applies the transform opts in explicitly.
    expect(
      verifyPermitForAction(out.permit!, treasuryKey, {
        audience: 'acct://treasury',
        intent: pay(500),
        now: NOW + 5,
        expectedEffect: 'transform',
      }).ok,
    ).toBe(true)
  })

  it('F5: an oversized permit token body is rejected fail-closed before the HMAC', () => {
    const node = makeNode()
    const out = node.admit({
      intent: pay(500),
      capabilities: [cap],
      session,
      audience: 'acct://treasury',
      now: NOW,
      observedAggregate: 0,
    })
    const treasuryKey = deriveAudiencePermitKey(session.sessionKey, 'acct://treasury')
    const huge = { ...out.permit!, body: new Uint8Array(9000) }
    const verdict = verifyPermitForAction(huge, treasuryKey, {
      audience: 'acct://treasury',
      intent: pay(500),
      now: NOW + 5,
    })
    expect(verdict.ok).toBe(false)
    expect(verdict.reasons.join(' ')).toContain('size bound')
  })

  it('PERMIT-001: a key-holding resource cannot forge a permit for another audience', () => {
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

    // Each resource is provisioned with ONLY its own audience-scoped key.
    const treasuryKey = deriveAudiencePermitKey(session.sessionKey, 'acct://treasury')
    const malloryKey = deriveAudiencePermitKey(session.sessionKey, 'acct://mallory')
    // Distinct audiences derive distinct, independent keys.
    expect(bytesToHex(treasuryKey)).not.toBe(bytesToHex(malloryKey))

    // The treasury permit verifies for treasury, and NOT under mallory's key.
    expect(
      verifyPermitForAction(permit, treasuryKey, {
        audience: 'acct://treasury',
        intent: pay(500),
        now: NOW + 5,
      }).ok,
    ).toBe(true)
    expect(
      verifyPermitForAction(permit, malloryKey, {
        audience: 'acct://mallory',
        intent: pay(500),
        now: NOW + 5,
      }).ok,
    ).toBe(false)

    // The attack: a malicious resource holding ONLY mallory's key re-MACs a
    // permit claiming the treasury audience. It can only sign under malloryKey,
    // so the treasury resource (holding treasuryKey) rejects the forgery.
    const forgedClaims: PermitClaims = {
      sessionId: session.sessionId,
      nonce: session.claims.nonce,
      audience: 'acct://treasury',
      actionHash: actionHash(pay(500)),
      tier: 2,
      exp: NOW + 30,
      evaluator: out.decision.evaluatorVersion,
      effect: 'allow',
    }
    const forged = issuePermit(forgedClaims, suite, malloryKey)
    expect(
      verifyPermitForAction(forged, treasuryKey, {
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

  it('denies a REVOKED capability at admission (REVOKE-ENFORCE-001)', () => {
    const node = makeNode()
    const revokedId = cap.chain[0]!.grant.id
    // Without revocation: allowed.
    expect(
      node.admit({
        intent: pay(500),
        capabilities: [cap],
        session,
        audience: 'acct://treasury',
        now: NOW,
        observedAggregate: 0,
      }).decision.effect,
    ).toBe('allow')
    // With the capability revoked (the explicit governance input): denied, no permit.
    const out = node.admit({
      intent: pay(500),
      capabilities: [cap],
      session,
      audience: 'acct://treasury',
      now: NOW,
      observedAggregate: 0,
      revoked: [revokedId],
    })
    expect(out.decision.effect).toBe('deny')
    expect(out.permit).toBeNull()
  })

  it('binds the session to a verified attestation when required (ATTEST-BIND-001)', () => {
    const rootSecret = randomBytes(32)
    const attPolicy = {
      expectedNonce: NONCE,
      now: NOW,
      trustedAttesters: [attesterKey.publicKey],
      acceptedFormats: ['software-dev'] as const,
    }
    const attNode = new PolarSeekNode({
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
    const reqFor = (s: Session) => ({
      intent: pay(500),
      capabilities: [cap],
      session: s,
      audience: 'acct://treasury',
      now: NOW,
      observedAggregate: 0,
    })

    // A fabricated session (self-chosen key, no node derivation) is DENIED.
    const fabricated: Session = {
      sessionId: 'sess-9',
      sessionKey: randomBytes(48),
      claims: evidence.claims,
    }
    expect(attNode.admit(reqFor(fabricated)).decision.effect).toBe('deny')

    // A node-established session (derived from VALID evidence) is admitted.
    const established = attNode.establishSession(evidence, attPolicy)
    expect(attNode.admit(reqFor(established)).decision.effect).toBe('allow')

    // INVALID evidence cannot establish a session at all (fail closed).
    const badSig = Uint8Array.from(evidence.sig)
    badSig[0] = (badSig[0] as number) ^ 0xff
    expect(() => attNode.establishSession({ ...evidence, sig: badSig }, attPolicy)).toThrow()
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
