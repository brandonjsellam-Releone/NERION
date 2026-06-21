// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { commitField, verifyDisclosure } from '../src/index.js'

describe('selective disclosure', () => {
  it('verifies a revealed field against its commitment', () => {
    const intent = { type: 'payment.transfer', amount: 500, counterparty: 'vendor-acme' }
    const commitment = commitField(intent)
    expect(verifyDisclosure(commitment, intent)).toBe(true)
  })

  it('rejects a different value', () => {
    const intent = { type: 'payment.transfer', amount: 500 }
    const commitment = commitField(intent)
    expect(verifyDisclosure(commitment, { type: 'payment.transfer', amount: 501 })).toBe(false)
  })

  it('is key-order independent (canonical encoding)', () => {
    expect(commitField({ a: 1, b: 2 })).toBe(commitField({ b: 2, a: 1 }))
  })

  // ── RCPT-001 / ADR-0014: salted (hiding) mode ──────────────────────────────
  it('a salt makes the commitment hiding and disclosable only with that salt', () => {
    const intent = { type: 'payment.transfer', amount: 500 }
    const salt = new Uint8Array(32).fill(7)
    const salted = commitField(intent, salt)
    // Salting changes the digest, so a low-entropy value is no longer the
    // brute-forceable unsalted hash of itself.
    expect(salted).not.toBe(commitField(intent))
    // Discloses with the salt; fails without it or with a wrong salt.
    expect(verifyDisclosure(salted, intent, salt)).toBe(true)
    expect(verifyDisclosure(salted, intent)).toBe(false)
    expect(verifyDisclosure(salted, intent, new Uint8Array(32).fill(8))).toBe(false)
  })

  it('different salts on the same value give different commitments (unlinkable)', () => {
    const v = { amount: 500 }
    expect(commitField(v, new Uint8Array(32).fill(1))).not.toBe(
      commitField(v, new Uint8Array(32).fill(2)),
    )
  })

  it('salted commitments stay key-order independent (canonical encoding)', () => {
    const salt = new Uint8Array(32).fill(9)
    expect(commitField({ a: 1, b: 2 }, salt)).toBe(commitField({ b: 2, a: 1 }, salt))
  })
})
