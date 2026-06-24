// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Property-based tests for settlement credits (MeteringLedger).
 *
 * Four invariants are verified with fast-check across random account names,
 * grant amounts, costs, and operation sequences:
 *
 *   CONSERVATION   — total credits before a valid settlement equals total credits after.
 *   NON-NEGATIVE   — no account balance ever goes negative.
 *   REPLAY IDEMPOTENT — applying the same grant or meter twice leaves the ledger in
 *                       the same state as applying it once (after the replay is
 *                       rejected).
 *   REPLAY REJECTED — replaying a consumed (account, nonce) grant or a metered
 *                     (account, ref) MUST throw SettlementError.
 */

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { MeteringLedger, SettlementError } from '../../settlement/src/index.js'

const suite = SUITE_IDS.PS_5
const issuer = signerFor(suite).keygen()

// ---------------------------------------------------------------------------
// Arbitraries
// ---------------------------------------------------------------------------

/**
 * A small set of account identifiers — diverse enough to exercise multi-account
 * scenarios without blowing up the property space.
 */
const accountArb = fc.constantFrom('agent://a', 'agent://b', 'agent://c', 'agent://d')

/** Positive grant amounts in a range that avoids Number overflow in test arithmetic. */
const amountArb = fc.integer({ min: 1, max: 1_000 })

/** Non-negative cost in the range [0, 500] — wide enough to include 0-cost meters. */
const costArb = fc.integer({ min: 0, max: 500 })

/** Unique-ish nonce strings. */
const nonceArb = fc.string({ minLength: 1, maxLength: 16 })

/** Unique-ish ref strings for metering. */
const refArb = fc.string({ minLength: 1, maxLength: 16 })

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Sum of all account balances in a freshly-snapshotted ledger state. */
function totalBalance(ledger: MeteringLedger, accounts: string[]): number {
  return accounts.reduce((sum, acct) => sum + ledger.balance(acct), 0)
}

// ---------------------------------------------------------------------------
// CONSERVATION: total credits before == total credits after any valid settlement.
//
// A "valid settlement" here means one or more grant()+meter() operations that
// each succeed.  The TOTAL of all account balances must equal the TOTAL granted
// minus the TOTAL metered, because credits are non-transferable — they can only
// be issued or consumed, never moved between accounts.
// ---------------------------------------------------------------------------
describe('CONSERVATION: total credits balance == granted minus metered', () => {
  it('total balance equals sum(grants) - sum(meters) across random operations', () => {
    fc.assert(
      fc.property(
        // A sequence of (account, amount, nonce) grant specs — make nonces unique
        // by including the index so we never accidentally trigger SETTLE-001 here.
        fc.array(fc.record({ account: accountArb, amount: amountArb }), {
          minLength: 1,
          maxLength: 10,
        }),
        // A parallel sequence of (account, cost, ref) meter specs.
        fc.array(fc.record({ account: accountArb, cost: costArb }), { minLength: 0, maxLength: 8 }),
        (grants, meters) => {
          const ledger = new MeteringLedger(suite, issuer)
          let totalGranted = 0
          let totalMetered = 0
          const accounts = new Set<string>()

          // Apply all grants (each gets a unique nonce via array index).
          for (let i = 0; i < grants.length; i++) {
            const { account, amount } = grants[i]!
            ledger.grant(account, amount, `grant-${i}`)
            totalGranted += amount
            accounts.add(account)
          }

          // Apply only meters where the account has enough balance.
          for (let i = 0; i < meters.length; i++) {
            const { account, cost } = meters[i]!
            if (ledger.balance(account) >= cost) {
              ledger.meter(account, cost, `meter-${i}`)
              totalMetered += cost
              accounts.add(account)
            }
          }

          const observed = totalBalance(ledger, [...accounts])
          expect(observed).toBe(totalGranted - totalMetered)
        },
      ),
      { numRuns: 60 },
    )
  })

  it('conservation holds after interleaved grant and meter on the same account', () => {
    fc.assert(
      fc.property(
        fc.array(amountArb, { minLength: 2, maxLength: 8 }),
        fc.array(fc.integer({ min: 0, max: 50 }), { minLength: 1, maxLength: 6 }),
        (amounts, costs) => {
          const acct = 'agent://single'
          const ledger = new MeteringLedger(suite, issuer)
          let totalGranted = 0
          let totalMetered = 0

          // Grant all credits first.
          for (let i = 0; i < amounts.length; i++) {
            ledger.grant(acct, amounts[i]!, `ng-${i}`)
            totalGranted += amounts[i]!
          }

          // Meter up to the available balance.
          for (let i = 0; i < costs.length; i++) {
            if (ledger.balance(acct) >= costs[i]!) {
              ledger.meter(acct, costs[i]!, `nm-${i}`)
              totalMetered += costs[i]!
            }
          }

          expect(ledger.balance(acct)).toBe(totalGranted - totalMetered)
        },
      ),
      { numRuns: 40 },
    )
  })
})

// ---------------------------------------------------------------------------
// NON-NEGATIVE: no account can go negative after a valid settlement.
//
// meter() is supposed to throw SettlementError when cost > balance. We verify
// that after every SUCCESSFUL operation the balance stays >= 0.
// ---------------------------------------------------------------------------
describe('NON-NEGATIVE: no account balance goes below zero', () => {
  it('balance is never negative after any mix of valid operations', () => {
    fc.assert(
      fc.property(
        fc.array(fc.record({ account: accountArb, amount: amountArb }), {
          minLength: 1,
          maxLength: 10,
        }),
        fc.array(fc.record({ account: accountArb, cost: costArb }), {
          minLength: 1,
          maxLength: 10,
        }),
        (grants, meters) => {
          const ledger = new MeteringLedger(suite, issuer)
          const accounts = new Set<string>()

          for (let i = 0; i < grants.length; i++) {
            const { account, amount } = grants[i]!
            ledger.grant(account, amount, `g${i}`)
            accounts.add(account)
          }

          for (let i = 0; i < meters.length; i++) {
            const { account, cost } = meters[i]!
            accounts.add(account)
            if (ledger.balance(account) >= cost) {
              ledger.meter(account, cost, `m${i}`)
            } else {
              // Expect a throw, and verify the balance did NOT go negative.
              expect(() => ledger.meter(account, cost, `m${i}`)).toThrow(SettlementError)
            }
          }

          // After every operation every known account must remain >= 0.
          for (const acct of accounts) {
            expect(ledger.balance(acct)).toBeGreaterThanOrEqual(0)
          }
        },
      ),
      { numRuns: 60 },
    )
  })

  it('meter on an account with zero balance throws and does not produce a negative balance', () => {
    fc.assert(
      fc.property(accountArb, fc.integer({ min: 1, max: 100 }), (account, cost) => {
        const ledger = new MeteringLedger(suite, issuer)
        // No grant — balance is 0.
        expect(ledger.balance(account)).toBe(0)
        expect(() => ledger.meter(account, cost, 'ref-zero')).toThrow(SettlementError)
        expect(ledger.balance(account)).toBe(0)
      }),
      { numRuns: 30 },
    )
  })
})

// ---------------------------------------------------------------------------
// REPLAY IDEMPOTENT: applying the same settlement twice produces the same state
// as applying it once (because the second application is rejected, leaving the
// state unchanged).
//
// After a replay is rejected the balance must equal what it was right after the
// first successful operation — neither double-credited nor double-charged.
// ---------------------------------------------------------------------------
describe('REPLAY IDEMPOTENT: state after one == state after two (replay rejected)', () => {
  it('grant replay is idempotent: balance unchanged after rejected re-grant', () => {
    fc.assert(
      fc.property(accountArb, amountArb, nonceArb, (account, amount, nonce) => {
        const ledger = new MeteringLedger(suite, issuer)
        ledger.grant(account, amount, nonce)
        const balanceAfterFirst = ledger.balance(account)

        // Second identical grant must throw (SETTLE-001).
        expect(() => ledger.grant(account, amount, nonce)).toThrow(SettlementError)

        // Balance must be identical to what it was after the FIRST grant.
        expect(ledger.balance(account)).toBe(balanceAfterFirst)
      }),
      { numRuns: 40 },
    )
  })

  it('meter replay is idempotent: balance unchanged after rejected re-meter', () => {
    fc.assert(
      fc.property(accountArb, amountArb, costArb, refArb, (account, grantAmount, cost, ref) => {
        // We need a sufficient balance for the first meter to succeed.
        const safeAmount = grantAmount + cost + 1
        const ledger = new MeteringLedger(suite, issuer)
        ledger.grant(account, safeAmount, 'setup-nonce')
        ledger.meter(account, cost, ref)
        const balanceAfterFirst = ledger.balance(account)

        // Second meter with the same ref must throw (SETTLE-METER-001).
        expect(() => ledger.meter(account, cost, ref)).toThrow(SettlementError)

        // Balance unchanged.
        expect(ledger.balance(account)).toBe(balanceAfterFirst)
      }),
      { numRuns: 40 },
    )
  })

  it('interleaved replays across multiple accounts leave the total balance unchanged', () => {
    fc.assert(
      fc.property(
        fc.array(fc.record({ account: accountArb, amount: amountArb, nonce: nonceArb }), {
          minLength: 2,
          maxLength: 6,
        }),
        (specs) => {
          const ledger = new MeteringLedger(suite, issuer)
          const dedupKey = new Set<string>()
          const accounts = new Set<string>()

          for (const { account, amount, nonce } of specs) {
            const key = JSON.stringify([account, nonce])
            if (dedupKey.has(key)) {
              // Replay — must throw and leave total balance unchanged.
              const before = totalBalance(ledger, [...accounts])
              expect(() => ledger.grant(account, amount, nonce)).toThrow(SettlementError)
              expect(totalBalance(ledger, [...accounts])).toBe(before)
            } else {
              ledger.grant(account, amount, nonce)
              dedupKey.add(key)
              accounts.add(account)
            }
          }
        },
      ),
      { numRuns: 40 },
    )
  })
})

// ---------------------------------------------------------------------------
// REPLAY REJECTED: a replayed (account, nonce) grant or (account, ref) meter
// MUST throw SettlementError — not silently succeed, not return a stale value.
// ---------------------------------------------------------------------------
describe('REPLAY REJECTED: replays always throw SettlementError', () => {
  it('grant replay always throws SettlementError (SETTLE-001)', () => {
    fc.assert(
      fc.property(
        accountArb,
        amountArb,
        nonceArb,
        fc.integer({ min: 1, max: 5 }), // how many extra re-grants to attempt
        (account, amount, nonce, attempts) => {
          const ledger = new MeteringLedger(suite, issuer)
          ledger.grant(account, amount, nonce)
          for (let i = 0; i < attempts; i++) {
            // Every attempt — regardless of amount — must throw.
            expect(() => ledger.grant(account, amount + i, nonce)).toThrow(SettlementError)
          }
        },
      ),
      { numRuns: 40 },
    )
  })

  it('meter replay always throws SettlementError (SETTLE-METER-001)', () => {
    fc.assert(
      fc.property(
        accountArb,
        fc.integer({ min: 100, max: 500 }), // large enough balance
        costArb,
        refArb,
        (account, grantAmount, cost, ref) => {
          const ledger = new MeteringLedger(suite, issuer)
          ledger.grant(account, grantAmount, 'setup')
          ledger.meter(account, Math.min(cost, ledger.balance(account)), ref)
          // Subsequent replay with ANY cost must throw.
          expect(() => ledger.meter(account, 0, ref)).toThrow(SettlementError)
          expect(() => ledger.meter(account, 1, ref)).toThrow(SettlementError)
        },
      ),
      { numRuns: 40 },
    )
  })

  it('grant with a DIFFERENT nonce on the same account succeeds after an initial grant', () => {
    fc.assert(
      fc.property(
        accountArb,
        amountArb,
        amountArb,
        // Two DISTINCT nonces — filter out coincidentally equal values.
        fc.string({ minLength: 4, maxLength: 12 }).chain((n1) =>
          fc
            .string({ minLength: 4, maxLength: 12 })
            .filter((n2) => n2 !== n1)
            .map((n2) => [n1, n2] as const),
        ),
        (account, amount1, amount2, [nonce1, nonce2]) => {
          const ledger = new MeteringLedger(suite, issuer)
          ledger.grant(account, amount1, nonce1)
          // A NEW nonce must succeed — the replay guard is keyed on (account, nonce), not account alone.
          expect(() => ledger.grant(account, amount2, nonce2)).not.toThrow()
          expect(ledger.balance(account)).toBe(amount1 + amount2)
        },
      ),
      { numRuns: 40 },
    )
  })

  it('meter with a DIFFERENT ref on the same account succeeds after an initial meter', () => {
    fc.assert(
      fc.property(
        accountArb,
        fc.integer({ min: 50, max: 200 }),
        fc.integer({ min: 0, max: 10 }),
        fc.string({ minLength: 4, maxLength: 12 }).chain((r1) =>
          fc
            .string({ minLength: 4, maxLength: 12 })
            .filter((r2) => r2 !== r1)
            .map((r2) => [r1, r2] as const),
        ),
        (account, grantAmount, cost, [ref1, ref2]) => {
          const ledger = new MeteringLedger(suite, issuer)
          ledger.grant(account, grantAmount, 'setup')
          ledger.meter(account, cost, ref1)
          // A NEW ref on the same account must not throw.
          expect(() =>
            ledger.meter(account, Math.min(cost, ledger.balance(account)), ref2),
          ).not.toThrow()
        },
      ),
      { numRuns: 40 },
    )
  })
})
