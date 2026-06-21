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
})
