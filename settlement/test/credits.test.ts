// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { MeteringLedger, SettlementError, tierCost } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const issuer = signerFor(suite).keygen()
const ACCT = 'agent://ops-1'

describe('non-transferable metering credits', () => {
  it('grants credits and exposes a verifiable, balance-bearing grant', () => {
    const ledger = new MeteringLedger(suite, issuer)
    const g = ledger.grant(ACCT, 100, 'n1')
    expect(ledger.balance(ACCT)).toBe(100)
    expect(ledger.verifyGrant(g)).toBe(true)
  })

  it('rejects a tampered grant signature', () => {
    const ledger = new MeteringLedger(suite, issuer)
    const g = ledger.grant(ACCT, 100, 'n1')
    const badSig = Uint8Array.from(g.sig)
    badSig[0] = (badSig[0] as number) ^ 0xff
    expect(ledger.verifyGrant({ ...g, sig: badSig })).toBe(false)
  })

  it('meters down by tier cost and refuses to overspend', () => {
    const ledger = new MeteringLedger(suite, issuer)
    ledger.grant(ACCT, 10, 'n1')
    ledger.meter(ACCT, tierCost(2), 'decision-abc') // T2 costs 5
    expect(ledger.balance(ACCT)).toBe(5)
    ledger.meter(ACCT, tierCost(2), 'decision-def')
    expect(ledger.balance(ACCT)).toBe(0)
    expect(() => ledger.meter(ACCT, tierCost(2), 'decision-ghi')).toThrow(SettlementError)
  })

  it('tier cost increases with risk', () => {
    expect(tierCost(0)).toBeLessThan(tierCost(1))
    expect(tierCost(1)).toBeLessThan(tierCost(2))
    expect(tierCost(2)).toBeLessThan(tierCost(3))
  })

  it('is non-transferable by construction (no transfer operation exists)', () => {
    const ledger = new MeteringLedger(suite, issuer)
    expect((ledger as unknown as Record<string, unknown>)['transfer']).toBeUndefined()
  })
})
