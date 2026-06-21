// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { authorizesIntent } from '../src/grant.js'
import type { ActionIntent, CapabilityGrant, EvalContext } from '../src/types.js'

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
