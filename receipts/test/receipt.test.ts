// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { TransparencyLog } from '../../translog/src/index.js'
import { commitField, verifyDisclosure } from '../../disclosure/src/index.js'
import {
  buildReceipt,
  receiptLeaf,
  verifyReceipt,
  verifyReceiptInclusion,
  verifyIntentDisclosure,
  INTENT_SALT_BYTES,
  type BuildReceiptParams,
} from '../src/index.js'

const issuer = signerFor(SUITE_IDS.PS_5).keygen()

const params = (over: Partial<BuildReceiptParams> = {}): BuildReceiptParams => ({
  suite: SUITE_IDS.PS_5,
  evaluatorVersion: 'polarseek-kernel/0.1.0+abc123',
  effect: 'allow',
  tier: 2,
  jurisdiction: 'US',
  timestamp: 1_750_000_000,
  intent: { type: 'payment.transfer', amount: 500 },
  capability: { id: 'cap-1' },
  policy: { version: '0.1.0' },
  inputHash: 'aa',
  decisionHash: 'bb',
  issuerSecretKey: issuer.secretKey,
  issuerPublicKey: issuer.publicKey,
  ...over,
})

describe('receipts', () => {
  it('build then verify succeeds and commits only hashes (no payload)', () => {
    const r = buildReceipt(params())
    expect(verifyReceipt(r)).toBe(true)
    expect(r.body.commitments.intent).toMatch(/^[0-9a-f]{64}$/)
    // The raw intent (type/amount) is committed by hash, not embedded.
    expect(JSON.stringify(r.body)).not.toContain('payment.transfer')
  })

  it('RCPT-PRIV-001: capability + policy commitments are salted → not cross-receipt-linkable', () => {
    const p = params() // same capability + policy for both receipts, but fresh per-receipt salts
    const r1 = buildReceipt(p)
    const r2 = buildReceipt(p)
    // A passive log observer cannot link two receipts by the SAME capability/policy — the published
    // commitments differ (previously they were unsalted, hence a stable cross-receipt fingerprint).
    expect(r1.body.commitments.capability).not.toBe(r2.body.commitments.capability)
    expect(r1.body.commitments.policy).not.toBe(r2.body.commitments.policy)
    // An AUTHORIZED party holding the salt can still recompute the commitment (disclosure); a passive
    // observer WITHOUT the salt cannot — matching the salted-intent pattern.
    expect(verifyDisclosure(r1.body.commitments.capability, p.capability, r1.intentSalt)).toBe(true)
    expect(verifyDisclosure(r1.body.commitments.policy, p.policy, r1.intentSalt)).toBe(true)
    expect(verifyDisclosure(r1.body.commitments.capability, p.capability)).toBe(false) // no salt
  })

  it('rejects a tampered receipt body', () => {
    const r = buildReceipt(params())
    const tampered = { ...r, body: { ...r.body, effect: 'deny' } }
    expect(verifyReceipt(tampered)).toBe(false)
  })

  it('rejects the wrong issuer key', () => {
    const r = buildReceipt(params())
    const other = signerFor(SUITE_IDS.PS_5).keygen()
    expect(verifyReceipt({ ...r, signerPublicKey: other.publicKey })).toBe(false)
  })

  it('RECEIPT-SUITE-THROW-001: an unknown body.suite fails CLOSED (false), never throwing', () => {
    const r = buildReceipt(params())
    const bogus = { ...r, body: { ...r.body, suite: 'PS-BOGUS' } }
    // signerFor('PS-BOGUS') throws UnknownSuiteError; verifyReceipt (and thus verifyReceiptInclusion)
    // must fail closed so an auditor/SDK verifying a batch of gossiped receipts never crashes on one
    // poisoned receipt (AAC cycle-5 completeness sweep — the sole verify-side signerFor left unwrapped).
    expect(() => verifyReceipt(bogus)).not.toThrow()
    expect(verifyReceipt(bogus)).toBe(false)
  })

  it('externally verifies signature + log inclusion with no operator trust', () => {
    const log = new TransparencyLog()
    // Interleave other entries so the receipt is not the only/first leaf.
    log.append(new TextEncoder().encode('other-0'))
    const r = buildReceipt(params())
    const { index } = log.append(receiptLeaf(r))
    log.append(new TextEncoder().encode('other-2'))

    const witness = log.proveInclusion(index)
    const verdict = verifyReceiptInclusion(r, witness, log.root(), issuer.publicKey)
    expect(verdict.ok).toBe(true)
    expect(verdict.reasons).toEqual([])
  })

  it('external verification fails on a wrong issuer key or wrong root', () => {
    const log = new TransparencyLog()
    const r = buildReceipt(params())
    const { index } = log.append(receiptLeaf(r))
    const witness = log.proveInclusion(index)
    const other = signerFor(SUITE_IDS.PS_5).keygen()

    expect(verifyReceiptInclusion(r, witness, log.root(), other.publicKey).ok).toBe(false)
    const empty = new TransparencyLog()
    empty.append(new TextEncoder().encode('different'))
    expect(verifyReceiptInclusion(r, witness, empty.root(), issuer.publicKey).ok).toBe(false)
  })

  // ── RCPT-001 / ADR-0014: salted, hiding intent commitment ──────────────────
  it('mints a fresh high-entropy salt per receipt, and never puts it in the leaf', () => {
    const r1 = buildReceipt(params())
    const r2 = buildReceipt(params())
    // Default length, fresh per build.
    expect(r1.intentSalt).toHaveLength(INTENT_SALT_BYTES)
    expect(bytesToHex(r1.intentSalt)).not.toBe(bytesToHex(r2.intentSalt))
    // Same intent, different salt -> different commitment (unlinkable across receipts).
    expect(r1.body.commitments.intent).not.toBe(r2.body.commitments.intent)
    // The salt is NOT published in the transparency-log leaf (the signed body).
    expect(bytesToHex(receiptLeaf(r1))).not.toContain(bytesToHex(r1.intentSalt))
    expect(JSON.stringify(r1.body)).not.toContain(bytesToHex(r1.intentSalt))
  })

  it('commits the intent as the SALTED hiding hash, not the brute-forceable unsalted one', () => {
    const intent = { type: 'payment.transfer', amount: 500 }
    const salt = new Uint8Array(INTENT_SALT_BYTES).fill(0xab)
    const r = buildReceipt(params({ intent, intentSalt: salt }))
    expect(r.body.commitments.intent).toBe(commitField(intent, salt))
    expect(r.body.commitments.intent).not.toBe(commitField(intent))
  })

  it('discloses the intent to a verifier holding the salt; an observer without it cannot (RCPT-001)', () => {
    const intent = { type: 'payment.transfer', amount: 500 }
    const r = buildReceipt(params({ intent }))
    // Authorized: holder reveals (intent, salt) -> matches.
    expect(verifyIntentDisclosure(r, intent)).toBe(true)
    // A log observer who knows the full intent but NOT the salt cannot recompute it
    // (this is the brute-force RCPT-001 closed: unsalted recompute no longer matches).
    expect(verifyDisclosure(r.body.commitments.intent, intent)).toBe(false)
    expect(
      verifyDisclosure(r.body.commitments.intent, intent, new Uint8Array(INTENT_SALT_BYTES)),
    ).toBe(false)
    // Binding intact: a tampered amount (same salt) is rejected.
    expect(verifyIntentDisclosure(r, { ...intent, amount: 501 })).toBe(false)
  })

  // ── RCPT-002: the replay input/decision hashes are ALSO salted ─────────────
  it('salts the input/decision-hash commitments so the leaf cannot re-leak the amount', () => {
    // The raw replay inputHash/decisionHash are SHA3 over the amount-bearing
    // KernelInput; published raw they re-leak the amount even though `intent` is
    // salted. They must be committed as salted, hiding values in the public leaf.
    const salt = new Uint8Array(INTENT_SALT_BYTES).fill(0xcd)
    const r = buildReceipt(params({ inputHash: 'aa', decisionHash: 'bb', intentSalt: salt }))
    expect(r.body.commitments.inputHash).toBe(commitField('aa', salt))
    expect(r.body.commitments.inputHash).not.toBe('aa') // not the raw replay hash
    expect(r.body.commitments.inputHash).not.toBe(commitField('aa')) // not the unsalted hash
    expect(r.body.commitments.decisionHash).toBe(commitField('bb', salt))
    expect(r.body.commitments.decisionHash).not.toBe('bb')

    // Fresh salt per receipt -> the same decision yields UNLINKABLE commitments.
    const r1 = buildReceipt(params({ inputHash: 'aa', decisionHash: 'bb' }))
    const r2 = buildReceipt(params({ inputHash: 'aa', decisionHash: 'bb' }))
    expect(r1.body.commitments.inputHash).not.toBe(r2.body.commitments.inputHash)
    expect(r1.body.commitments.decisionHash).not.toBe(r2.body.commitments.decisionHash)
  })
})
