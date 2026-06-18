import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { TransparencyLog } from '../../translog/src/index.js'
import {
  buildReceipt,
  receiptLeaf,
  verifyReceipt,
  verifyReceiptInclusion,
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
})
