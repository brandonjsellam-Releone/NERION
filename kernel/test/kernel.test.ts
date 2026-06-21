// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { issueRoot } from '../../capabilities/src/index.js'
import type { ActionIntent } from '../../capabilities/src/index.js'
import { decide, decideWithAuthorizer, tierOf, DEFAULT_POLICY } from '../src/index.js'
import type { KernelInput, Policy } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)
const authority = signer.keygen()
const holder = signer.keygen()
const holderHex = bytesToHex(holder.publicKey)

const root = issueRoot(
  {
    subject: holderHex,
    actions: ['payment.transfer', 'data.read'],
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

const PAY: ActionIntent = {
  type: 'payment.transfer',
  resource: 'acct://t',
  counterparty: 'a',
  amount: 10,
}
const READ: ActionIntent = { type: 'data.read', resource: 'doc://x' }

describe('deterministic risk tiering', () => {
  it('maps actions to tiers and defaults conservatively', () => {
    expect(tierOf(READ, DEFAULT_POLICY)).toBe(0)
    expect(tierOf(PAY, DEFAULT_POLICY)).toBe(2)
    expect(tierOf({ type: 'actuation.physical.arm', resource: 'r' }, DEFAULT_POLICY)).toBe(3)
    expect(tierOf({ type: 'totally.unknown', resource: 'r' }, DEFAULT_POLICY)).toBe(3)
    // PS-KERNEL-03: a crafted near-prefix must NOT inherit the low tier.
    expect(tierOf({ type: 'data.readX', resource: 'r' }, DEFAULT_POLICY)).toBe(3)
    expect(tierOf({ type: 'data.read', resource: 'r' }, DEFAULT_POLICY)).toBe(0)
  })
})

describe('decideWithAuthorizer — the real authorizer for the receipt (RECEIPT-CAP-001)', () => {
  const decoy = issueRoot(
    {
      subject: holderHex,
      actions: ['infra.deploy'],
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

  it('returns the capability that actually authorized, not capabilities[0]', () => {
    // decoy (index 0) does NOT authorize a data.read; root (index 1) does.
    const out = decideWithAuthorizer(input(READ, { capabilities: [decoy, root] }))
    expect(out.decision.effect).toBe('allow')
    expect(out.authorizingCapability).toBe(root)
    expect(out.authorizingCapability).not.toBe(decoy)
    // decide() returns the byte-identical decision — the authorizer rides OUTSIDE it.
    expect(decide(input(READ, { capabilities: [decoy, root] }))).toEqual(out.decision)
  })

  it('returns a null authorizer on deny', () => {
    const out = decideWithAuthorizer(input(READ, { capabilities: [] }))
    expect(out.decision.effect).toBe('deny')
    expect(out.authorizingCapability).toBe(null)
  })
})

describe('admission decisions', () => {
  it('allows an authorized T2 action and attaches T2 obligations', () => {
    const d = decide(input(PAY))
    expect(d.effect).toBe('allow')
    expect(d.tier).toBe(2)
    expect(d.obligations).toContain('nearline-receipt')
    expect(d.obligations).toContain('step-up-approval')
  })

  it('allows an authorized T0 read with no obligations', () => {
    const d = decide(input(READ))
    expect(d.effect).toBe('allow')
    expect(d.tier).toBe(0)
    expect(d.obligations).toEqual([])
  })

  it('default-denies when no capability is supplied', () => {
    expect(decide(input(PAY, { capabilities: [] })).effect).toBe('deny')
  })

  it('fails closed when there is no trusted root', () => {
    expect(decide(input(PAY, { trustedRoots: [] })).effect).toBe('deny')
  })

  it('honors a policy denylist even with a valid capability', () => {
    const policy: Policy = { ...DEFAULT_POLICY, denyActions: ['payment.transfer'] }
    expect(decide(input(PAY, { policy })).effect).toBe('deny')
  })

  it('emits transform when policy marks the action for transformation', () => {
    const policy: Policy = { ...DEFAULT_POLICY, transformActions: ['data.read'] }
    expect(decide(input(READ, { policy })).effect).toBe('transform')
  })

  it('receipt-implies-authorization: an allow only ever follows authorization', () => {
    // Over-ceiling / wrong-holder inputs must never produce allow.
    expect(decide(input(PAY, { holder: 'deadbeef' })).effect).toBe('deny')
  })

  it('binds a pinned evaluator version that changes with the policy', () => {
    const a = decide(input(PAY)).evaluatorVersion
    const b = decide(input(PAY)).evaluatorVersion
    expect(a).toBe(b)
    expect(a).toMatch(/^polarseek-kernel\//)
    const policy: Policy = { ...DEFAULT_POLICY, version: '9.9.9' }
    expect(decide(input(PAY, { policy })).evaluatorVersion).not.toBe(a)
  })
})
