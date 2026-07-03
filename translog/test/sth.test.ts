// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import {
  TransparencyLog,
  signTreeHead,
  verifyTreeHead,
  detectEquivocation,
  checkAppendOnly,
} from '../src/index.js'

const suite = SUITE_IDS.PS_5
const op = signerFor(suite).keygen()
const data = (s: string): Uint8Array => new TextEncoder().encode(s)

describe('signed tree heads', () => {
  it('signs and verifies an STH', () => {
    const log = new TransparencyLog()
    log.append(data('a'))
    const sth = signTreeHead(log.size(), log.root(), suite, op)
    expect(verifyTreeHead(sth, op.publicKey)).toBe(true)
  })

  it('rejects an STH under the wrong operator key', () => {
    const log = new TransparencyLog()
    log.append(data('a'))
    const sth = signTreeHead(log.size(), log.root(), suite, op)
    const other = signerFor(suite).keygen()
    expect(verifyTreeHead(sth, other.publicKey)).toBe(false)
  })

  it('STH-SUITE-001: a relabeled suite fails verification (suite is bound into the signed head)', () => {
    const log = new TransparencyLog()
    log.append(data('a'))
    const sth = signTreeHead(log.size(), log.root(), SUITE_IDS.PS_5, op)
    expect(verifyTreeHead(sth, op.publicKey)).toBe(true)
    // PS-1 / PS-5 / PS-5-HQC all share the ML-DSA-87 signer, so before the fix a PS-5 STH
    // relabeled to either still verified. With the suite folded into the signed bytes, it fails.
    expect(verifyTreeHead({ ...sth, suite: SUITE_IDS.PS_1 }, op.publicKey)).toBe(false)
    expect(verifyTreeHead({ ...sth, suite: SUITE_IDS.PS_5_HQC }, op.publicKey)).toBe(false)
  })

  it('STH-SUITE-THROW-001: an unknown/inactive suite fails CLOSED, never throwing (completeness sweep)', () => {
    const log = new TransparencyLog()
    log.append(data('a'))
    const sth = signTreeHead(log.size(), log.root(), suite, op)
    // signerFor('PS-BOGUS') throws UnknownSuiteError; the EXPORTED verifyTreeHead must fail closed
    // (not crash a direct external caller) on a bogus gossiped STH suite.
    expect(() => verifyTreeHead({ ...sth, suite: 'PS-BOGUS' }, op.publicKey)).not.toThrow()
    expect(verifyTreeHead({ ...sth, suite: 'PS-BOGUS' }, op.publicKey)).toBe(false)
  })
})

describe('split-view / equivocation detection', () => {
  it('flags one operator presenting two AUTHENTIC roots at the same size', () => {
    const a = signTreeHead(3, data('root-A'), suite, op)
    const b = signTreeHead(3, data('root-B'), suite, op)
    const eq = detectEquivocation([a, b])
    expect(eq.length).toBe(1)
    expect(eq[0]?.size).toBe(3)
  })

  it('does not flag consistent, distinct sizes', () => {
    const a = signTreeHead(3, data('root-A'), suite, op)
    const b = signTreeHead(4, data('root-B'), suite, op)
    expect(detectEquivocation([a, b]).length).toBe(0)
  })

  it('STH-VERIFY-001: a FORGED STH cannot frame an honest operator', () => {
    const opHex = Buffer.from(op.publicKey).toString('hex')
    const genuine = signTreeHead(5, data('honest-root'), suite, op)
    // An attacker (no access to op's secret key) fabricates a conflicting STH at the same operator+size.
    const forged = {
      operator: opHex,
      size: 5,
      rootHex: '00'.repeat(32),
      suite,
      sig: new Uint8Array(64),
    }
    // The forged STH fails self-verification → discarded → the honest operator is NOT reported.
    expect(detectEquivocation([genuine, forged])).toEqual([])
    // Sanity: two GENUINE conflicting STHs ARE flagged.
    const genuine2 = signTreeHead(5, data('honest-root-2'), suite, op)
    expect(detectEquivocation([genuine, genuine2]).length).toBe(1)
  })
})

describe('append-only monitoring across STHs', () => {
  it('accepts a genuine growth and rejects a rewritten history', () => {
    const log = new TransparencyLog()
    for (let i = 0; i < 3; i++) log.append(data(`r${i}`))
    const older = signTreeHead(log.size(), log.root(), suite, op)
    for (let i = 3; i < 7; i++) log.append(data(`r${i}`))
    const newer = signTreeHead(log.size(), log.root(), suite, op)
    const proof = log.proveConsistency(older.size).proof
    expect(checkAppendOnly(older, newer, proof)).toBe(true)

    // A forged "newer" with a different root must fail.
    const forged = { ...newer, rootHex: '00'.repeat(32) }
    expect(checkAppendOnly(older, forged, proof)).toBe(false)
  })
})
