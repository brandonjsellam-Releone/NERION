// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { MeteringLedger, SettlementError } from '../src/index.js'

/**
 * Settlement hardening — Team Apex (2026-06-21), unanimous 3-seat findings:
 *  - SETTLE-001: grant() now records consumed (account, nonce) pairs, so a signed
 *    CreditGrant cannot be replayed to double-credit.
 *  - SETTLE-002: verifyGrant(g, trustedIssuer) binds the grant to a trusted issuer;
 *    without that argument it is only a signature self-check (anyone can self-sign a
 *    grant under their own key).
 */
const suite = SUITE_IDS.PS_5
const issuer = signerFor(suite).keygen()
const issuerHex = bytesToHex(issuer.publicKey)
const ACCT = 'agent://ops-1'

describe('settlement hardening (SETTLE-001 / SETTLE-002)', () => {
  it('SETTLE-001: a reused (account, nonce) is rejected — no double-credit', () => {
    const ledger = new MeteringLedger(suite, issuer)
    ledger.grant(ACCT, 100, 'n1')
    expect(() => ledger.grant(ACCT, 100, 'n1')).toThrow(SettlementError)
    expect(ledger.balance(ACCT)).toBe(100) // credited exactly once
  })

  it('SETTLE-001: distinct nonces still credit independently; same nonce on another account is fine', () => {
    const ledger = new MeteringLedger(suite, issuer)
    ledger.grant(ACCT, 100, 'n1')
    ledger.grant(ACCT, 50, 'n2')
    expect(ledger.balance(ACCT)).toBe(150)
    ledger.grant('agent://ops-2', 10, 'n1') // (account, nonce) is the key, not nonce alone
    expect(ledger.balance('agent://ops-2')).toBe(10)
  })

  it('SETTLE-002: verifyGrant binds the trusted issuer', () => {
    const ledger = new MeteringLedger(suite, issuer)
    const g = ledger.grant(ACCT, 100, 'n1')
    expect(ledger.verifyGrant(g, issuerHex)).toBe(true)
    expect(ledger.verifyGrant(g, bytesToHex(signerFor(suite).keygen().publicKey))).toBe(false)
  })

  it('SETTLE-002: an attacker self-signed grant is rejected against the trusted issuer', () => {
    const attacker = signerFor(suite).keygen()
    const forged = new MeteringLedger(suite, attacker).grant(ACCT, 1_000_000, 'evil')
    const real = new MeteringLedger(suite, issuer)
    // Bound to the REAL issuer -> rejected (issuer mismatch), even though it is validly self-signed.
    expect(real.verifyGrant(forged, issuerHex)).toBe(false)
    // Unbound self-check still returns true (the documented footgun: callers MUST pin the issuer).
    expect(real.verifyGrant(forged)).toBe(true)
    // ...and it is correctly bound to the attacker's own key.
    expect(real.verifyGrant(forged, bytesToHex(attacker.publicKey))).toBe(true)
  })

  it('SETTLE-METER-001: a reused (account, ref) cannot be metered twice — no account drain', () => {
    const ledger = new MeteringLedger(suite, issuer)
    ledger.grant(ACCT, 100, 'n1')
    ledger.meter(ACCT, 5, 'decision-x')
    expect(ledger.balance(ACCT)).toBe(95)
    // Replaying the SAME (account, ref) must NOT decrement again (a replayed permit
    // cannot drain the account).
    expect(() => ledger.meter(ACCT, 5, 'decision-x')).toThrow(SettlementError)
    expect(ledger.balance(ACCT)).toBe(95) // charged exactly once
    // A distinct ref meters independently; the same ref on another account is independent.
    ledger.meter(ACCT, 5, 'decision-y')
    expect(ledger.balance(ACCT)).toBe(90)
    ledger.grant('agent://ops-2', 10, 'n1')
    ledger.meter('agent://ops-2', 5, 'decision-x')
    expect(ledger.balance('agent://ops-2')).toBe(5)
  })

  it('SETTLE-METER-001: a failed (insufficient) meter does not consume the ref (retryable)', () => {
    const ledger = new MeteringLedger(suite, issuer)
    ledger.grant(ACCT, 3, 'n1')
    // Insufficient for cost 5 -> throws, and the ref is NOT recorded as metered.
    expect(() => ledger.meter(ACCT, 5, 'decision-z')).toThrow(/insufficient/)
    // After a top-up the SAME ref meters fine (it was never consumed by the failed call).
    ledger.grant(ACCT, 10, 'n2')
    ledger.meter(ACCT, 5, 'decision-z')
    expect(ledger.balance(ACCT)).toBe(8) // 3 + 10 - 5
  })
})
