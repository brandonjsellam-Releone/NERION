// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { narrow, isAttenuationOf, authorizesIntent } from '../src/grant.js'
import type { Attenuation } from '../src/grant.js'
import type { ActionIntent, CapabilityGrant, EvalContext, RiskTier } from '../src/types.js'

/**
 * The formally-relevant property: ATTENUATION NEVER AMPLIFIES AUTHORITY.
 * A narrowed (delegated) grant can authorize only a subset of what its parent
 * authorizes — across every dimension, for every intent and context.
 */

const ACTIONS = ['pay', 'read', 'deploy', 'delete']
const CPS = ['alice', 'bob', 'carol']

const tierArb = fc.constantFrom<RiskTier>(0, 1, 2, 3)

const grantArb: fc.Arbitrary<CapabilityGrant> = fc
  .record({
    start: fc.nat(50),
    len: fc.nat(50),
    actions: fc.subarray(ACTIONS),
    perActionCeiling: fc.option(fc.integer({ min: 0, max: 1000 }), { nil: null }),
    aggregateCap: fc.option(fc.integer({ min: 0, max: 2000 }), { nil: null }),
    counterparties: fc.option(fc.subarray(CPS), { nil: null }),
    maxTier: tierArb,
    delegable: fc.boolean(),
  })
  .map((g) => ({
    id: 'P',
    issuer: 'I',
    subject: 'S',
    actions: g.actions,
    perActionCeiling: g.perActionCeiling,
    aggregateCap: g.aggregateCap,
    counterparties: g.counterparties,
    maxTier: g.maxTier,
    notBefore: g.start,
    notAfter: g.start + g.len,
    delegable: g.delegable,
  }))

const attenArb = fc
  .record({
    actions: fc.option(fc.subarray(ACTIONS), { nil: undefined }),
    perActionCeiling: fc.option(fc.integer({ min: 0, max: 1000 }), { nil: undefined }),
    aggregateCap: fc.option(fc.integer({ min: 0, max: 2000 }), { nil: undefined }),
    counterparties: fc.option(fc.subarray(CPS), { nil: undefined }),
    maxTier: fc.option(tierArb, { nil: undefined }),
    delegable: fc.option(fc.boolean(), { nil: undefined }),
  })
  .map((r) => r as unknown as Attenuation)

const intentArb: fc.Arbitrary<ActionIntent> = fc
  .record({
    type: fc.constantFrom(...ACTIONS, 'unknown'),
    cp: fc.option(fc.constantFrom(...CPS, 'mallory'), { nil: undefined }),
    amount: fc.option(fc.integer({ min: 0, max: 3000 }), { nil: undefined }),
  })
  .map((x) => ({
    type: x.type,
    resource: 'r',
    ...(x.cp !== undefined ? { counterparty: x.cp } : {}),
    ...(x.amount !== undefined ? { amount: x.amount } : {}),
  }))

const ctxArb: fc.Arbitrary<EvalContext> = fc
  .record({ now: fc.nat(120), tier: tierArb, agg: fc.integer({ min: 0, max: 2000 }) })
  .map((c) => ({ now: c.now, tier: c.tier, observedAggregate: c.agg }))

const bind = (parent: CapabilityGrant) => ({ id: 'C', issuer: parent.subject, subject: 'S2' })

describe('attenuation properties', () => {
  it('narrow() always yields a valid attenuation of its parent', () => {
    fc.assert(
      fc.property(grantArb, attenArb, (parent, r) => {
        expect(isAttenuationOf(narrow(parent, r, bind(parent)), parent)).toBe(true)
      }),
    )
  })

  it('attenuation never amplifies: child authorizes ⇒ parent authorizes', () => {
    fc.assert(
      fc.property(grantArb, attenArb, intentArb, ctxArb, (parent, r, intent, ctx) => {
        const child = narrow(parent, r, bind(parent))
        if (authorizesIntent(child, intent, ctx)) {
          expect(authorizesIntent(parent, intent, ctx)).toBe(true)
        }
      }),
    )
  })

  it('isAttenuationOf rejects a broadened ceiling', () => {
    const parent: CapabilityGrant = {
      id: 'P',
      issuer: 'I',
      subject: 'S',
      actions: ['pay'],
      perActionCeiling: 100,
      aggregateCap: null,
      counterparties: ['alice'],
      maxTier: 1,
      notBefore: 0,
      notAfter: 100,
      delegable: true,
    }
    const broadened: CapabilityGrant = { ...parent, id: 'C', issuer: 'S', perActionCeiling: 1000 }
    expect(isAttenuationOf(broadened, parent)).toBe(false)
  })
})
