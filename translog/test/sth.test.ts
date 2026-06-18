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
})

describe('split-view / equivocation detection', () => {
  it('flags one operator presenting two roots at the same size', () => {
    const opHex = Buffer.from(op.publicKey).toString('hex')
    const a = { operator: opHex, size: 3, rootHex: 'aa', suite, sig: new Uint8Array() }
    const b = { operator: opHex, size: 3, rootHex: 'bb', suite, sig: new Uint8Array() }
    const eq = detectEquivocation([a, b])
    expect(eq.length).toBe(1)
    expect(eq[0]?.size).toBe(3)
  })

  it('does not flag consistent, distinct sizes', () => {
    const opHex = Buffer.from(op.publicKey).toString('hex')
    const a = { operator: opHex, size: 3, rootHex: 'aa', suite, sig: new Uint8Array() }
    const b = { operator: opHex, size: 4, rootHex: 'bb', suite, sig: new Uint8Array() }
    expect(detectEquivocation([a, b]).length).toBe(0)
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
