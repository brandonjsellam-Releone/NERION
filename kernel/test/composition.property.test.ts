// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * COMPOSITION — cross-branch integration test (frontier-integration-v1).
 *
 * The 9 frontier upgrades were each gate-green in ISOLATION; the council's #1 gap was that nothing
 * exercised them TOGETHER. This asserts the governance invariants compose on a single decision flow —
 * gov-policy-algebra (well-formed policy) + gov-params-blindness (decision ignores params) +
 * gov-manifest-bind (declared ⟺ applied) + saf3 fail-closed (deny ⟺ no verified authorizer) — and
 * that the crypto frontier composes too (pqc4 key-committing seal round-trips and its domain-sep
 * labels are recognized by the pqc-domain-registry). All on the merged tree.
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import {
  signerFor,
  SUITE_IDS,
  getKem,
  implementedKemIds,
  sealToKem,
  openSealed,
} from '../../crypto/src/index.js'
import { isRegisteredLabel, isExcludedLiteral } from '../../crypto/src/domain-labels.js'
import { issueRoot } from '../../capabilities/src/index.js'
import type { ActionIntent } from '../../capabilities/src/index.js'
import type { ActionManifest, RiskClass } from '../../capabilities/src/profile.js'
import {
  decide,
  decideWithAuthorizer,
  DEFAULT_POLICY,
  analyzePolicy,
  expectedRiskClass,
  expectedPolicyBinding,
  checkManifestConsistency,
} from '../src/index.js'
import type { KernelInput, Policy } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)
const authority = signer.keygen()
const holder = signer.keygen()
const holderHex = bytesToHex(holder.publicKey)

const root = issueRoot(
  {
    subject: holderHex,
    actions: ['payment.transfer'],
    perActionCeiling: null,
    aggregateCap: null,
    counterparties: null,
    maxTier: 3,
    notBefore: 0,
    notAfter: 10_000_000_000,
    delegable: false,
  },
  suite,
  authority,
)

const PAY: ActionIntent = {
  type: 'payment.transfer',
  resource: 'acct://t',
  counterparty: 'a',
  amount: 10,
}

const input = (intent: ActionIntent, over: Partial<KernelInput> = {}): KernelInput => ({
  intent,
  capabilities: [root],
  policy: DEFAULT_POLICY,
  trustedRoots: [authority.publicKey],
  now: 1000,
  observedAggregate: 0,
  holder: holderHex,
  ...over,
})

const manifestFor = (
  intent: ActionIntent,
  policy: Policy,
  over: Partial<ActionManifest> = {},
): ActionManifest => ({
  verbId: 'fin.payment.transfer',
  authorityScope: 'acct://t',
  riskClass: expectedRiskClass(intent, policy),
  policyHash: expectedPolicyBinding(policy),
  replayDomain: 'd',
  expiry: 10_000_000_000,
  ...over,
})

describe('COMPOSITION — governance frontier invariants hold jointly', () => {
  it('policy-algebra + params-blindness + manifest-bind + fail-closed compose on an ALLOW', () => {
    expect(analyzePolicy(DEFAULT_POLICY).conflictFree).toBe(true) // gov-policy-algebra
    const baseline = decide(input(PAY))
    const withParams = decide(
      input({ ...PAY, params: { secret: 'x', amount: 0, type: 'data.read' } }),
    )
    expect(withParams).toEqual(baseline) // gov-params-blindness: params ignored
    expect(baseline.effect).toBe('allow')
    expect(decideWithAuthorizer(input(PAY)).authorizingCapability).not.toBeNull() // saf3: authorizer on allow
    expect(
      checkManifestConsistency(manifestFor(PAY, DEFAULT_POLICY), PAY, DEFAULT_POLICY).consistent,
    ).toBe(true) // gov-manifest-bind
  })

  it('params-blindness ignores adversarial params WHILE manifest-bind still catches a laundered manifest', () => {
    const laundered = manifestFor(PAY, DEFAULT_POLICY, { riskClass: 'T0' as RiskClass }) // PAY is T2
    expect(decide(input({ ...PAY, params: { riskClass: 'T0', tier: 0 } })).effect).toBe('allow')
    expect(checkManifestConsistency(laundered, PAY, DEFAULT_POLICY).consistent).toBe(false)
  })

  it('fail-closed composes: no capability denies with a null authorizer under a well-formed policy', () => {
    expect(analyzePolicy(DEFAULT_POLICY).conflictFree).toBe(true)
    const out = decideWithAuthorizer(input(PAY, { capabilities: [] }))
    expect(out.decision.effect).toBe('deny')
    expect(out.authorizingCapability).toBeNull()
  })

  it('crypto composes: a key-committing seal round-trips AND its domain-sep labels are registry-known', () => {
    const kemId = implementedKemIds()[0]!
    const kem = getKem(kemId)
    const r = kem.keygen()
    const pt = new TextEncoder().encode('compose')
    const sealed = sealToKem(r.publicKey, pt, {
      suite: 'PS-5',
      kemId,
      senderId: 's',
      recipientId: 'r1',
    })
    expect(Buffer.from(openSealed(sealed, r, { suite: 'PS-5', recipientId: 'r1' }))).toEqual(
      Buffer.from(pt),
    )
    expect(sealed.keyCommitment.length).toBe(32) // pqc4
    expect(isRegisteredLabel('polarseek/kem-seal')).toBe(true) // pqc-domain-registry knows the seal label
    expect(isExcludedLiteral('polarseek/kem-seal/key-commitment/v1')).toBe(true) // and classifies the salt
  })
})
