// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { authorizesIntent } from '../src/grant.js'
import type { ActionIntent, CapabilityGrant, EvalContext, RiskTier } from '../src/types.js'

/**
 * CAP-WINDOW-001 (Team Apex hand-audit, 2026-06-22): authorizesIntent guarded the CLOCK
 * (ctx.now) for finiteness but NOT the signed grant's own notBefore/notAfter. A grant with a
 * non-finite notAfter (NaN/Infinity) made `ctx.now > grant.notAfter` false, silently skipping
 * expiry so the grant authorized FOREVER — the KERNEL-TIME-001 / GOV-WINDOW-001 class, the exact
 * grant.ts follow-up the GOV-WINDOW-001 fix flagged. Now fails closed on a malformed grant window.
 */
const grant = (over: Partial<CapabilityGrant> = {}): CapabilityGrant => ({
  id: 'g',
  issuer: 'I',
  subject: 'S',
  actions: ['pay'],
  perActionCeiling: 1000,
  aggregateCap: null,
  counterparties: null,
  maxTier: 3,
  notBefore: 0,
  notAfter: 1000,
  delegable: false,
  ...over,
})
const intent: ActionIntent = { type: 'pay', resource: 'acct://x', amount: 10 }
const ctx = (now: number): EvalContext => ({ now, tier: 0, observedAggregate: 0 })

describe('CAP-WINDOW-001 — authorizesIntent fails closed on a malformed grant window', () => {
  it('authorizes inside a well-formed window, denies a genuinely expired one (sanity)', () => {
    expect(authorizesIntent(grant(), intent, ctx(500))).toBe(true)
    expect(authorizesIntent(grant(), intent, ctx(2000))).toBe(false)
  })

  it('denies a non-finite grant notAfter — it must NOT authorize forever', () => {
    expect(authorizesIntent(grant({ notAfter: NaN }), intent, ctx(10_000))).toBe(false)
    expect(authorizesIntent(grant({ notAfter: Infinity }), intent, ctx(10_000))).toBe(false)
  })

  it('denies a non-finite grant notBefore', () => {
    expect(authorizesIntent(grant({ notBefore: NaN }), intent, ctx(500))).toBe(false)
    expect(authorizesIntent(grant({ notBefore: Number.NEGATIVE_INFINITY }), intent, ctx(500))).toBe(
      false,
    )
  })
})

/**
 * CAP-NUM-001 (Team Apex missed-classes sweep, 2026-06-28): authorizesIntent guarded ctx.tier and
 * the grant WINDOW for finiteness but used the signed grant's own maxTier / ceilings raw. A
 * non-finite maxTier made `ctx.tier > maxTier` false (tier cap skipped) and a non-finite non-null
 * ceiling made `amount > ceiling` false (amount cap skipped), so a malformed (trusted-signed) grant
 * authorized ANY tier / amount. Now fails closed; isAttenuationOf likewise rejects malformed grants
 * so monotonicity never depends on incidental NaN-comparison behavior.
 */
describe('CAP-NUM-001 — authorizesIntent fails closed on a malformed grant maxTier / ceiling', () => {
  const ctxT = (tier: RiskTier, observedAggregate = 0): EvalContext => ({
    now: 500,
    tier,
    observedAggregate,
  })

  it('denies a non-finite grant maxTier — the tier cap must not be skipped', () => {
    expect(authorizesIntent(grant({ maxTier: 1 }), intent, ctxT(2))).toBe(false) // sanity: cap denies
    expect(authorizesIntent(grant({ maxTier: NaN as unknown as RiskTier }), intent, ctxT(2))).toBe(
      false,
    )
    expect(
      authorizesIntent(grant({ maxTier: Infinity as unknown as RiskTier }), intent, ctxT(2)),
    ).toBe(false)
  })

  it('denies a non-finite (non-null) ceiling — the amount cap must not be skipped', () => {
    const big: ActionIntent = { type: 'pay', resource: 'acct://x', amount: 1_000_000 }
    expect(authorizesIntent(grant({ perActionCeiling: 100 }), big, ctxT(0))).toBe(false) // sanity
    expect(authorizesIntent(grant({ perActionCeiling: NaN }), big, ctxT(0))).toBe(false)
    expect(authorizesIntent(grant({ aggregateCap: NaN }), big, ctxT(0))).toBe(false)
    expect(authorizesIntent(grant({ aggregateCap: Infinity }), big, ctxT(0))).toBe(false)
  })
})
